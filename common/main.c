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
#include "epoll_timerfd_utilities.h"

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
static void TimerEventHandler(EventData *eventData);
static int Initialize(void);

// Initialization/Cleanup
#include "options.h"
#include "connection.h"
#include "eventloop_timer_utilities.h"
static EventLoop *eventLoop = NULL;

// Cloud
#include "cloud.h"
static const char *CloudResultToString(Cloud_Result result);
static bool isConnected = false;
static const char *serialNumber = "leosphere_001";
static void ConnectionChangedCallbackHandler(bool connected);
static ExitCode InitEventLoopAndConnectCloud(void);



/*
// Initialization/Cleanup


static void ClosePeripheralsAndHandlers(void);

*/



// File descriptors - initialized to invalid value
 int epollFd = -1;
static int timerFd = -1;



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
    if ((Networking_IsNetworkingReady(&isNetworkingReady) == -1) || !isNetworkingReady) {
        Log_Debug("WARNING: Network is not ready. Device cannot connect until network is ready.\n");
    }
    exitCode = Options_ParseArgs(argc, argv);

    /*
    if (Initialize() != 0) {
        exitCode=ExitCode_Connection_TimerStart;
    }
    */
    exitCode = InitEventLoopAndConnectCloud();

    if (exitCode != ExitCode_Success) {
        return exitCode;
    }

    /*
    serverState = webServer_Start(epollFd, localServerIpAddress.s_addr, LocalTcpServerPort,
                                  serverBacklogSize, MainServerStoppedHandler);
    if (serverState == NULL)
    {
        exitCode = ExitCode_WebServer_Start;
        return exitCode;
    }
    */

    // now it is both epoll and eventloop, will sort it out later
    while (exitCode == ExitCode_Success) {
        /*
        if (WaitForEventAndCallHandler(epollFd) != 0) {
            exitCode = ExitCode_Main_EventLoopFail;
        }
        */
       
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
 

/// <summary>
///     The timer event handler.
/// </summary>
static void TimerEventHandler(EventData *eventData)
{
    //TODO: old one using epoll... right now it is still used by the tcp server listener

    if (ConsumeTimerFdEvent(timerFd) != 0) {
        exitCode = ExitCode_Connection_TimerConsume;
        return;
    }
}


/// <summary>
///     Set up SIGTERM termination handler, set up epoll event handling, configure network
///     interface, start SNTP server and TCP server.
/// </summary>
/// <returns>0 on success, or -1 on failure</returns>
// event handler data structures. Only the event handler field needs to be populated.
static EventData afterPrcoessTimerEventData = {.eventHandler = &TimerEventHandler};
static int Initialize(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = TerminationHandler;
    sigaction(SIGTERM, &action, NULL);

    epollFd = CreateEpollFd();
    if (epollFd < 0) {
        return -1;
    }

    // Check network interface status at the specified period until it is ready.
	// wlan should set longer check interval (around 8s) otherwise will hang
    struct timespec checkInterval = {10, 0};
    timerFd = CreateTimerFdAndAddToEpoll(epollFd, &checkInterval, &afterPrcoessTimerEventData, EPOLLIN);
    if (timerFd < 0) {
        return -1;
    }

    return 0;
}

static ExitCode InitEventLoopAndConnectCloud(void)
{
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

/// <summary>
///     Shut down TCP server and close epoll event handler.
/// </summary>
static void ShutDownServerAndCleanup(void)
{
    webServer_ShutDown(serverState);
    CloseFdAndPrintError(epollFd, "Epoll");
    CloseFdAndPrintError(timerFd, "Timer");
}



static void MainServerStoppedHandler(webServer_StopReason reason) {
	ServerStoppedHandler(reason);
}









