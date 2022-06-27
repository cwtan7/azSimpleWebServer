
/* Copyright (c) SC Lee. All rights reserved.
	Licensed under the GNU GPLv3 License. 
	
	part of code copies from Microsoft Sample Private Network Services 
	@link https://github.com/Azure/azure-sphere-samples/tree/master/Samples/PrivateNetworkServices
	 Copyright (c) Microsoft Corporation. All rights reserved.
          Licensed under the MIT License. 
	*/




#pragma once

#include "netinet/in.h"

#include "eventloop_timer_utilities.h"
#include "exitcodes.h"

#define MAX_GET_PARAMETER   	16

#if defined(ENABLE_BASE64_ENCODE)
#define MAX_LINE_INPUT      	(36 * 1024)         // 36KB Max size
#define B64_ENCODE_BUF_SIZE 	(52 * 1024)         // +40% margin for Base64 encode output
#else
#define MAX_LINE_INPUT      	(58 * 1024)         // 64KB Max size
#endif
#define FILEREADBUFFERSIZE 		128
#define MAX_SOCKET_BUFF_SIZE	(8 * 1024)			// Socket Buffer Size @ 8KB

#define MIME_NONE -1
#define MIME_TEXT 1
#define MIME_DATA 2


// Ethernet / TCP server settings.
/// <summary>Reason why the TCP server stopped.</summary>
typedef enum {
    /// <summary>The echo server stopped because the client closed the connection.</summary>
    EchoServer_StopReason_ClientClosed,
    /// <summary>The echo server stopped because an error occurred.</summary>
    EchoServer_StopReason_Error
} webServer_StopReason;

/// <summary>
/// Bundles together state about an active echo server.
/// This should be allocated with <see cref="EchoServer_Start" /> and freed with
/// <see cref="EchoServer_ShutDown" />. The client should not directly modify member variables.
/// </summary>
typedef struct {
    EventLoop *eventLoop;
    /// <summary>Socket which listens for incoming connections.</summary>
    int listenFd;
    /// <summary>Invoked when a new connection is received.</summary>
    EventRegistration *listenEventReg;
    /// <summary>Accept socket. Only one client socket supported at a time.</summary>
    int clientFd;
    /// <summary>
    ///     Invoked when server receives data from or sends data to the client.
    /// </summary>
    EventRegistration *clientEventReg;
    /// <summary>Number of characters received from client.</summary>
    size_t inLineSize;
    /// <summary>Data received from client.</summary>
    char* httpMethod;
    size_t contentLength;
    char input[MAX_LINE_INPUT];
#if defined(ENABLE_BASE64_ENCODE)
    /// <summary>Scratch buffer for encoding input size +40%. Need to revisit how to make it more robust and dynamic according to input max size</summary>
    char encode_b64_buf[B64_ENCODE_BUF_SIZE];
    /// <summary>Encoded Size.</summary>
    size_t encoded_size;
#endif
    /// <summary>Payload to write to client.</summary>
    uint8_t *txPayload;
    /// <summary>Number of bytes to write to client.</summary>
    size_t txPayloadSize;
    /// <summary>Number of characters from paylod which have been written to client so
    /// far.</summary>
    size_t txBytesSent;
	/// <summary>is HTTP header</summary>
	size_t isHttp;
	/// <summary> POST Content
	char post[256];
    /// <summary>
    /// <para>Callback to invoke when the server stops processing connections.</para>
    /// <para>When this callback is invoked, the owner should clean up the server with
    /// <see cref="EchoServer_ShutDown" />.</para>
    /// <param name="reason">Why the server stopped.</param>
    /// </summary>
    void (*shutdownCallback)(webServer_StopReason reason);
} webServer_ServerState;

/// <summary>
///     <para>Open a non-blocking TCP listening socket on the supplied IP address and port.</para>
///     <param name="eventLoopInstance">Event loop which will invoke IO callbacks.</param>
///     <param name="ipAddr">IP address to which the listen socket is bound.</param>
///     <param name="port">TCP port to which the socket is bound.</param>
///     <param name="backlogSize">Listening socket queue length.</param>
///     <param name="shutdownCallback">Callback to invoke when server shuts down.</param>
///     <param name="callerExitCode">
///         On failure, set to specific failure code. Undefined on success.
///     </param>
///     <returns>
///         Server state which is used to manage the server's resources, NULL on failure.
///         Should be disposed of with <see cref="EchoServer_ShutDown" />.
///     </returns>
/// </summary>
webServer_ServerState *webServer_Start(EventLoop *eventLoopInstance, in_addr_t ipAddr, uint16_t port,
                                         int backlogSize,
                                         void (*shutdownCallback)(webServer_StopReason),
                                         ExitCode *callerExitCode);

/// <summary>
/// <para>Closes any resources which were allocated by the supplied server. This includes
/// closing listen and accepted sockets, and freeing any heap memory that was allocated.</para>
/// <param name="serverState">Server state allocated with <see cref="EchoServer_Start" />.</param>
/// </summary>
void webServer_ShutDown(webServer_ServerState *serverState);

/** @brief : Debug Log can be show on both debug serial and web interface
  * @retval i: receiver status
  */
int LogWebDebug(const char* fmt, ...);