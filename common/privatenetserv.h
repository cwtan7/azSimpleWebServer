#include "web_tcp_server.h"

/// <summary>
///     Set up SIGTERM termination handler, set up event loop, configure network
///     interface, start SNTP server and TCP server.
/// </summary>
/// <returns>
///     ExitCode_Success if all resources were allocated successfully; otherwise another
///     ExitCode value which indicates the specific failure.
/// </returns>
ExitCode InitializeAndLaunchServers(EventLoop *eventLoop);

/// <summary>
///     Shut down TCP server and close event handler.
/// </summary>
void ShutDownServerAndCleanup(void);

/// <summary>
///     Called when the TCP server needs a warm restart.
/// </summary>
void ServerRestartHandler(webServer_StopReason reason);

/// <summary>
///     Return Server State
/// </summary>
webServer_ServerState *GetServerState(void);

/// <summary>
///     Get Ethernet / TCP server information / attributes.
/// <summary>
void GetTcpServerIPInfo(struct in_addr *TcpServerIpAddr, uint16_t *TcpServerPort);

void SetNetworkInterface(char *network_inf_type);
void SetIPMode(char *ip_mode);
void SetIPAddress(char *ip_addr);
void SetIPSubnetMask(char *ip_subnetmask);
void SetGwAddress(char *gw_ipaddr);
void SetIPServerPort(char *server_port);