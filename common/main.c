/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

// This sample C application shows how to set up services on a private Ethernet network. It
// configures the network with a static IP address, starts the DHCP service allowing dynamically
// assigning IP address and network configuration parameters, enables the SNTP service allowing
// other devices to synchronize time via this device, and sets up a TCP server.
//
// It uses the API for the following Azure Sphere application libraries:
// - log (messages shown in Visual Studio's Device Output window during debugging)
// - networking (sets up private Ethernet configuration)

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

// applibs_versions.h defines the API struct versions to use for applibs APIs.
#include "applibs_versions.h"

#include <applibs/log.h>
#include <applibs/eventloop.h>
#include <applibs/networking.h>
#include <applibs/wificonfig.h>

#include "exitcodes.h"

#include "mt3620_avnet_dev.h"

#include "web_tcp_server.h"


static volatile sig_atomic_t exitCode = ExitCode_Success;
static void ExitCodeCallbackHandler(ExitCode ec);


static void ShutDownServerAndCleanup(void);
static void MainServerStoppedHandler(webServer_StopReason reason);

// Initialization/Cleanup
#include "options.h"
#include "connection.h"
#include "eventloop_timer_utilities.h"
static EventLoop *eventLoop = NULL;

// Cloud
#include "cloud.h"
static const char *CloudResultToString(Cloud_Result result);
static bool isConnected = false;
static const char *serialNumber = "AzSphere-SimpleWebServ-001";
static void ConnectionChangedCallbackHandler(bool connected);
static ExitCode InitEventLoopAndConnectCloud(void);
static void ShutDownServerAndCleanup(void);


/// <summary>
///     Signal handler for termination requests. This handler must be async-signal-safe.
/// </summary>
static void TerminationHandler(int signalNumber)
{
    // Don't use Log_Debug here, as it is not guaranteed to be async-signal-safe.
    exitCode = ExitCode_TermHandler_SigTerm;
}

static void ExitCodeCallbackHandler(ExitCode ec)
{
    exitCode = ec;
}

/// <summary>
///     Main entry point for this application.
/// </summary>
int main(int argc, char *argv[])
{
    Log_Debug("INFO: Web setting server application starting.\n");
    //check network
    bool isNetworkingReady = false;
    if ((Networking_IsNetworkingReady(&isNetworkingReady) == -1) || !isNetworkingReady)
    {
        Log_Debug("WARNING: Network is not ready. Device cannot connect until network is ready.\n");
    }
    exitCode = Options_ParseArgs(argc, argv);
    if (exitCode != ExitCode_Success)
    {
        return exitCode;
    }

    exitCode = InitEventLoopAndConnectCloud();
    if (exitCode != ExitCode_Success)
    {
        return exitCode;
    }

    
    serverState = webServer_Start(eventLoop, localServerIpAddress.s_addr, LocalTcpServerPort,
                                  serverBacklogSize, MainServerStoppedHandler);
    if (serverState == NULL)
    {
        exitCode = ExitCode_WebServer_Start;
        return exitCode;
    }
    
    while (exitCode == ExitCode_Success) {
        EventLoop_Run_Result result = EventLoop_Run(eventLoop, -1, true);
        // Continue if interrupted by signal, e.g. due to breakpoint being set.
        if (result == EventLoop_Run_Failed && errno != EINTR) {
            exitCode = ExitCode_Main_EventLoopFail;
        }
    }

    ShutDownServerAndCleanup();
    Log_Debug("INFO: Application exiting.\n");
    return exitCode;
}


static ExitCode InitEventLoopAndConnectCloud(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = TerminationHandler;
    sigaction(SIGTERM, &action, NULL);

    eventLoop = EventLoop_Create();
    if (eventLoop == NULL) {
        Log_Debug("Could not create event loop.\n");
        return ExitCode_Init_EventLoop;
    }

    void *connectionContext = Options_GetConnectionContext();

    return Cloud_Initialize(eventLoop, connectionContext, ExitCodeCallbackHandler,
                            NULL,
                            NULL, ConnectionChangedCallbackHandler);
}



static const char *CloudResultToString(Cloud_Result result)
{
    switch (result) {
    case Cloud_Result_OK:
        return "OK";
    case Cloud_Result_NoNetwork:
        return "No network connection available";
    case Cloud_Result_OtherFailure:
        return "Other failure";
    }

    return "Unknown Cloud_Result";
}

static void ConnectionChangedCallbackHandler(bool connected)
{
    isConnected = connected;

    if (isConnected) {
        Cloud_Result result = Cloud_SendDeviceDetails(serialNumber);
        if (result != Cloud_Result_OK) {
            Log_Debug("WARNING: Could not send device details to cloud: %s\n",
                      CloudResultToString(result));
        }
    }
}

static void ShutDownServerAndCleanup(void)
{
    webServer_ShutDown();
    Cloud_Cleanup();
    EventLoop_Close(eventLoop);
}



static void MainServerStoppedHandler(webServer_StopReason reason) {
	ServerStoppedHandler(reason);
}









