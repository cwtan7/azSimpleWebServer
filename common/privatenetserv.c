/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

// This sample C application shows how to set up services on a private Ethernet network. It
// configures the network with a static IP address, starts the DHCP service allowing dynamically
// assigning IP address and network configuration parameters, enables the SNTP service allowing
// other devices to synchronize time via this device, and sets up a TCP server.
//
// It uses the API for the following Azure Sphere application libraries:
// - log (displays messages in the Device Output window during debugging)
// - networking (sets up private Ethernet configuration)

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>

// applibs_versions.h defines the API struct versions to use for applibs APIs.
#include "applibs_versions.h"
#include "eventloop_timer_utilities.h"

#include <applibs/log.h>
#include <applibs/networking.h>

// The following #include imports a "sample appliance" hardware definition. This provides a set of
// named constants such as SAMPLE_BUTTON_1 which are used when opening the peripherals, rather
// that using the underlying pin names. This enables the same code to target different hardware.
//
// By default, this app targets hardware that follows the MT3620 Reference Development Board (RDB)
// specification, such as the MT3620 Dev Kit from Seeed Studio. To target different hardware, you'll
// need to update the TARGET_HARDWARE variable in CMakeLists.txt - see instructions in that file.
//
// You can also use hardware definitions related to all other peripherals on your dev board because
// the sample_appliance header file recursively includes underlying hardware definition headers.
// See https://aka.ms/azsphere-samples-hardwaredefinitions for further details on this feature.
#include <hw/sample_appliance.h>

#include "web_tcp_server.h"
#include "exitcodes.h"
#include "privatenetserv.h"

static void ServerStoppedHandler(webServer_StopReason reason);
static ExitCode EnableCurrentNetworkInterface(void);
static ExitCode ListAvailableNetworkInterfaces(void);
static ExitCode CheckNetworkStatus(void);
static ExitCode ConfigureNetworkInterfaceIpMode(const char *interfaceName);
static ExitCode CheckNetworkStackStatusAndLaunchServers(void);
static void CheckStatusTimerEventHandler(EventLoopTimer *timer);

static EventLoop *privatenetserv_eventLoop = NULL;
static EventLoopTimer *checkStatusTimer = NULL;

static bool isNetworkStackReady = false;
webServer_ServerState *serverState = NULL;

// Termination state
static volatile sig_atomic_t exitCode = ExitCode_Success;

// Ethernet / TCP server settings.
static struct in_addr localServerIpAddress;
static struct in_addr subnetMask;
static struct in_addr gatewayIpAddress;
static uint16_t LocalTcpServerPort;
static int serverBacklogSize = 3;
static bool isDynamicIP = true; // default is Dynamic IP

/// <summary>
///     The available network interface device names.
/// </summary>
#define NET_INTERFACE_WLAN "wlan0"
#define NET_INTERFACE_ETHERNET "eth0"

#define NET_IP_MODE_STATIC "static"
#define NET_IP_MODE_DYNAMIC "dynamic"

// User configuration.
const char *currentNetInterface = NET_INTERFACE_WLAN;
    

// Get ServerState
webServer_ServerState * GetServerState(void)
{
    return serverState;
}

// Get Ethernet / TCP server information / attributes.
void GetTcpServerIPInfo(struct in_addr *TcpServerIpAddr, uint16_t *TcpServerPort)
{
    *TcpServerIpAddr = localServerIpAddress;
    *TcpServerPort = LocalTcpServerPort;
}

/// <summary>
///     Called when the TCP server needs a warm restart.
/// </summary>
void ServerRestartHandler(webServer_StopReason reason)
{

	ExitCode localExitCode;
    webServer_ServerState *_serverState = NULL;
	
    webServer_ShutDown(serverState);  //should we call "ShutDownServerAndCleanup"?

    // Start the TCP server.
    _serverState = webServer_Start(privatenetserv_eventLoop, localServerIpAddress.s_addr, LocalTcpServerPort,
                                  serverBacklogSize, ServerStoppedHandler, &localExitCode);
    if (_serverState == NULL)
    {
        exitCode = ExitCode_StoppedHandler_Stopped;
        return;
    }

    // Log_Debug("INFO: TCP server Restarting: %s\n", reason);
}

/// <summary>
///     Called when the TCP server stops processing messages from clients.
/// </summary>
static void ServerStoppedHandler(webServer_StopReason reason)
{
    const char *reasonText;
    switch (reason) {
    case EchoServer_StopReason_ClientClosed:
        reasonText = "client closed the connection.";
        break;

    case EchoServer_StopReason_Error:
        reasonText = "an error occurred. See previous log output for more information.";
        break;

    default:
        reasonText = "unknown reason.";
        break;
    }

    Log_Debug("INFO: TCP server stopped: %s\n", reasonText);
    exitCode = ExitCode_StoppedHandler_Stopped;
}

/// <summary>
///     Shut down TCP server and close event handler.
/// </summary>
void ShutDownServerAndCleanup(void)
{
    webServer_ShutDown(serverState);

    DisposeEventLoopTimer(checkStatusTimer);
}

/// <summary>
///     Attempts to retrieve the current network interface's IP address.
/// </summary>
/// <param name=""></param>
char *GetIpAddress(void)
{
    static char ip_address[sizeof("000.000.000.000")];

    // Find the assigned IP address by scanning all the interfaces.
    struct ifaddrs *addr_list;
    *ip_address = 0;

    if (getifaddrs(&addr_list) != 0) {
        Log_Debug("ERROR: getifaddrs() failed: errno=%d (%s)\n", errno, strerror(errno));

    } else {

        struct ifaddrs *it = addr_list;
        for (int n = 0; it != NULL; it = it->ifa_next, ++n) {
            if (NULL == it->ifa_addr)
                continue;

            if (0 == strncmp(it->ifa_name, currentNetInterface, strlen(currentNetInterface))) {
                if (AF_INET == it->ifa_addr->sa_family) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)it->ifa_addr;
                    strncpy(ip_address, inet_ntoa(addr->sin_addr), sizeof(ip_address) - 1);
                }
            }
        }
    }
    freeifaddrs(addr_list);

    return ip_address;
}

/// <summary>
///     Attempts to enable the current network interface, specified in the `currentNetInterface`
///     global variable.
/// </summary>
/// <param name=""></param>
static ExitCode EnableCurrentNetworkInterface(void)
{
    Log_Debug("INFO: Attempting to enable network interface '%s'.\n", currentNetInterface);
    int res = Networking_SetInterfaceState(currentNetInterface, true);
    
    if (-1 == res)
    {
        if (errno == EAGAIN)
        {
            Log_Debug("INFO: The networking stack isn't ready yet, will try again later.\n");
            return ExitCode_Success;
        } 
        else 
        {
            Log_Debug("ERROR: enabling network interface '%s': errno= %d (%s).\n", currentNetInterface,
                    errno, strerror(errno));
            return ExitCode_CheckStatus_SetInterfaceState;
        }
    } 
    else
    {
        Log_Debug("INFO: Network interface is now set to '%s'.\n", currentNetInterface);

        // If the network is on Wi-Fi, then disable the Ethernet interface (and vice versa).
        bool onWiFi = (0 == strcmp(currentNetInterface, NET_INTERFACE_WLAN));
        Networking_SetInterfaceState(onWiFi ? NET_INTERFACE_ETHERNET : NET_INTERFACE_WLAN, false);
        if (-1 == res)
        {
            Log_Debug("ERROR: Disabling network interface '%s': errno=%d (%s).\n",
                      onWiFi ? NET_INTERFACE_ETHERNET : NET_INTERFACE_WLAN, errno, strerror(errno));
            return ExitCode_CheckStatus_SetInterfaceState;
        }

        return ExitCode_Success;
    }
}

/// <summary>
///     Query and display information about all available network interfaces.
/// </summary>
/// <returns>
///     ExitCode_Success on success; otherwise another ExitCode value which indicates
///     the specific failure.
/// </returns>
static ExitCode ListAvailableNetworkInterfaces(void)
{
// Display total number of network interfaces.
    ssize_t count = Networking_GetInterfaceCount();
    if (count == -1) {
        Log_Debug("ERROR: Networking_GetInterfaceCount: errno=%d (%s)\n", errno, strerror(errno));
        return ExitCode_CheckStatus_GetInterfaceCount;
    }
    Log_Debug("INFO: Networking_GetInterfaceCount: count=%zd\n", count);

    // Read current status of all interfaces.
    size_t bytesRequired = ((size_t)count) * sizeof(Networking_NetworkInterface);
    Networking_NetworkInterface *interfaces = malloc(bytesRequired);
    if (!interfaces) {
        abort();
    }

    ssize_t actualCount = Networking_GetInterfaces(interfaces, (size_t)count);
    if (actualCount == -1) {
        Log_Debug("ERROR: Networking_GetInterfaces: errno=%d (%s)\n", errno, strerror(errno));
    }
    Log_Debug("INFO: Networking_GetInterfaces: actualCount=%zd\n", actualCount);

    // Print detailed description of each interface.
    for (ssize_t i = 0; i < actualCount; ++i) {
        Log_Debug("INFO: interface #%zd\n", i);

        // Print the interface's name.
        Log_Debug("INFO:   interfaceName=\"%s\"\n", interfaces[i].interfaceName);

        // Print whether the interface is enabled.
        Log_Debug("INFO:   isEnabled=\"%d\"\n", interfaces[i].isEnabled);

        // Print the interface's configuration type.
        Networking_IpType ipType = interfaces[i].ipConfigurationType;
        const char *typeText;
        switch (ipType)
        {
            case Networking_IpType_DhcpNone:
                typeText = "DhcpNone";
                break;
            case Networking_IpType_DhcpClient:
                typeText = "DhcpClient";
                break;
            default:
                typeText = "unknown-configuration-type";
                break;
        }
        Log_Debug("INFO:   ipConfigurationType=%d (%s)\n", ipType, typeText);

        // Print the interface's medium.
        Networking_InterfaceMedium_Type mediumType = interfaces[i].interfaceMediumType;
        const char *mediumText;
        switch (mediumType)
        {
            case Networking_InterfaceMedium_Unspecified:
                mediumText = "unspecified";
                break;
            case Networking_InterfaceMedium_Wifi:
                mediumText = "Wi-Fi";
                break;
            case Networking_InterfaceMedium_Ethernet:
                mediumText = "Ethernet";
                break;
            default:
                mediumText = "unknown-medium";
                break;
        }
        Log_Debug("INFO:   interfaceMediumType=%d (%s)\n", mediumType, mediumText);

        // Print the interface connection status
        Networking_InterfaceConnectionStatus status;
        int result = Networking_GetInterfaceConnectionStatus(interfaces[i].interfaceName, &status);
        if (result != 0) {
            Log_Debug("ERROR: Networking_GetInterfaceConnectionStatus: errno=%d (%s)\n", errno,
                      strerror(errno));
            return ExitCode_CheckStatus_GetInterfaceConnectionStatus;
        }
        Log_Debug("INFO:   interfaceStatus=0x%02x\n", status);
    }

    free(interfaces);
    
    return ExitCode_Success;
}

/// <summary>
///     Check network status and display information about all available network interfaces.
/// </summary>
/// <returns>
///     ExitCode_Success on success; otherwise another ExitCode value which indicates
///     the specific failure.
/// </returns>
static ExitCode CheckNetworkStatus(void)
{
    // Ensure the necessary network interface is enabled.
    ExitCode result = EnableCurrentNetworkInterface();

    if (result == ExitCode_Success)
    {
        isNetworkStackReady = true;
    }

    // Uncomment to Show Network Interfaces
    result = ListAvailableNetworkInterfaces();

    return (result);
}

/// <summary>
///     Configure the specified network interface with a static IP address.
/// </summary>
/// <param name="interfaceName">
///     The name of the network interface to be configured.
/// </param>
/// <returns>
///     ExitCode_Success on success; otherwise another ExitCode value which indicates
///     the specific failure.
/// </returns>
static ExitCode ConfigureNetworkInterfaceIpMode(const char *interfaceName)
{
    Networking_IpConfig ipConfig;

    Networking_IpConfig_Init(&ipConfig);
	
    if (isDynamicIP)
    {
        Networking_IpConfig_EnableDynamicIp(&ipConfig);
    }
    else
    {
        Networking_IpConfig_EnableStaticIp(&ipConfig, localServerIpAddress, subnetMask,
                                       gatewayIpAddress);
    }

    int result = Networking_IpConfig_Apply(interfaceName, &ipConfig);
    Networking_IpConfig_Destroy(&ipConfig);
    if (result != 0) {
        Log_Debug("ERROR: Networking_IpConfig_Apply: %d (%s)\n", errno, strerror(errno));
        return ExitCode_ConfigureStaticIp_IpConfigApply;
    }
    Log_Debug("INFO: Set %s IP address on network interface: %s.\n", 
                (isDynamicIP ? NET_IP_MODE_DYNAMIC : NET_IP_MODE_STATIC), interfaceName);

    return ExitCode_Success;
}


/// <summary>
///     Configure network interface, start SNTP server and TCP server.
/// </summary>
/// <returns>
///     ExitCode_Success on success; otherwise another ExitCode value which indicates
///     the specific failure.
/// </returns>
static ExitCode CheckNetworkStackStatusAndLaunchServers(void)
{
    // Use static IP addressing to configure network interface.
    ExitCode localExitCode;

    // Check the network stack readiness and display available interfaces when it's ready.
    localExitCode = CheckNetworkStatus();
    if (localExitCode != ExitCode_Success)
    {
        return localExitCode;
    }

    // The network stack is ready, so unregister the timer event handler and launch servers.
    if (isNetworkStackReady)
    {
        DisarmEventLoopTimer(checkStatusTimer);

        // Use static IP addressing to configure network interface.
        localExitCode = ConfigureNetworkInterfaceIpMode(currentNetInterface);
        if (localExitCode != ExitCode_Success) {
            return localExitCode;
        }

        if (!localServerIpAddress.s_addr)
        { 
            inet_aton(GetIpAddress(), &localServerIpAddress);
        }
        Log_Debug("INFO: Assigned IP address [%s].\n", GetIpAddress());

        // Start the TCP server.
        serverState = webServer_Start(privatenetserv_eventLoop, localServerIpAddress.s_addr, LocalTcpServerPort,
                                       serverBacklogSize, ServerStoppedHandler, &localExitCode);
        if (serverState == NULL) {
            return localExitCode;
        }
    }

    return ExitCode_Success;
}

/// <summary>
///     The timer event handler.
/// </summary>
static void CheckStatusTimerEventHandler(EventLoopTimer *timer)
{
    if (ConsumeEventLoopTimerEvent(timer) != 0) {
        exitCode = ExitCode_TimerHandler_Consume;
        return;
    }

    // Check whether the network stack is ready.
    if (!isNetworkStackReady) {
        ExitCode localExitCode = CheckNetworkStackStatusAndLaunchServers();
        if (localExitCode != ExitCode_Success) {
            exitCode = localExitCode;
            return;
        }
    }
}

/// <summary>
///     Set up SIGTERM termination handler, set up event loop, configure network
///     interface, start SNTP server and TCP server.
/// </summary>
/// <returns>
///     ExitCode_Success if all resources were allocated successfully; otherwise another
///     ExitCode value which indicates the specific failure.
/// </returns>
ExitCode InitializeAndLaunchServers(EventLoop *eventLoop)
{
#if 0 //cw_dbg
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = TerminationHandler;
    sigaction(SIGTERM, &action, NULL);

    eventLoop = EventLoop_Create();
    if (eventLoop == NULL) {
        return ExitCode_InitLaunch_EventLoop;
    }
#endif
    // Initialize and keep a local copy of the global event loop which will be use at a later stage
    privatenetserv_eventLoop = eventLoop;

    // Check network interface status at the specified period until it is ready.
    static const struct timespec checkInterval = {.tv_sec = 1, .tv_nsec = 0};
    
    checkStatusTimer =
        CreateEventLoopPeriodicTimer(eventLoop, CheckStatusTimerEventHandler, &checkInterval);
    if (checkStatusTimer == NULL) {
        return ExitCode_InitLaunch_Timer;
    }

    return ExitCode_Success;
}

void SetNetworkInterface(char *net_if_type)
{
    // Check network interface type validity before assigning.
    if( ((int)strcmp(net_if_type, NET_INTERFACE_WLAN) == 0) ||
        ((int)strcmp(net_if_type, NET_INTERFACE_ETHERNET) == 0) )
    {
        currentNetInterface = net_if_type;
    }
    else
    {
        Log_Debug("ERROR: Invalid Network I/F Type %s\n", net_if_type);
    }

    Log_Debug("INFO: Network Interface - %s\n", net_if_type);
    // TODO: return with error_code?
    return;
}

void SetIPMode(char *ip_mode)
{
    if((int)strcmp(ip_mode,NET_IP_MODE_DYNAMIC) == 0)
    {
        isDynamicIP = true;
    }
    else     if((int)strcmp(ip_mode,NET_IP_MODE_STATIC) == 0)
    {
        isDynamicIP = false;
    }
    else
    {
        Log_Debug("ERROR: Invalid IP Mode - %s\n", ip_mode);
        return;
        // set error_code?
    }

    Log_Debug("INFO: IP Mode - %s\n", ip_mode);
    // TODO: return with error_code?
    return;
}

void SetIPAddress(char *ip_addr)
{
    if (!isDynamicIP)
    {
        inet_aton(ip_addr, &localServerIpAddress);
    }
    return;
}

void SetIPSubnetMask(char *ip_subnetmask)
{
    if (!isDynamicIP)
    {
        inet_aton(ip_subnetmask, &subnetMask);
    }
    return;
}

void SetGwAddress(char *gw_ipaddr)
{
    if (!isDynamicIP)
    {
        inet_aton(gw_ipaddr, &gatewayIpAddress);
    }
    return;
}

void SetIPServerPort(char *server_port)
{
    LocalTcpServerPort = (uint16_t)strtol(server_port, NULL, 10);
}
