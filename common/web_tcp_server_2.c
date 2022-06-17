/* Copyright (c) SC Lee. All rights reserved.
	Licensed under the GNU GPLv3 License.

	part of code copies from Microsoft Sample Private Network Services
	@link https://github.com/Azure/azure-sphere-samples/tree/master/Samples/PrivateNetworkServices
	 Copyright (c) Microsoft Corporation. All rights reserved.
		  Licensed under the MIT License.
	*/

/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#define _GNU_SOURCE // required for asprintf
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include "applibs_versions.h"
#include <applibs/log.h>
#include <applibs/networking.h>
#include <applibs/storage.h>
#include <applibs/wificonfig.h>
#include "web_tcp_server.h"
#include "cloud.h"

static bool isNetworkStackReady = false;
webServer_ServerState *serverState = NULL;

#define MAX_WEBLOG 2048

char weblogBuffer[MAX_WEBLOG];

int weblogBuffer_n = 0;
uint8_t isWebDebug = 0;

#define AFTER_NONE 0
#define AFTER_FORGET 1
#define AFTER_CHANGEWIFI 2
int afterprocess = AFTER_NONE;

char *new_wifi_ssid = NULL;
char *new_wifi_psk = NULL;

int timerFd = -1;

// Support functions.
static void HandleListenEvent(EventLoop *el, int fd, EventLoop_IoEvents events, void *context);
static void LaunchRead(void);
static void HandleClientReadEvent(EventLoop *el, int fd, EventLoop_IoEvents events, void *context);
static void LaunchWrite(void);
static void LaunchWriteGET(void);
static void LaunchWritePOST(void);
static void HandleClientWriteEvent(EventLoop *el, int fd, EventLoop_IoEvents events, void *context);
static int OpenIpV4Socket(in_addr_t ipAddr, uint16_t port, int sockType);
static void ReportError(const char *desc);
static void StopServer(webServer_StopReason reason);
static void CloseFdAndPrintError(int fd, const char *fdName);
static const char *CloudResultToString(Cloud_Result result);

/// <summary>
///     Called when the TCP server stops processing messages from clients.
/// </summary>
void ServerStoppedHandler(webServer_StopReason reason)
{
	const char *reasonText;
	switch (reason)
	{
	case EchoServer_StopReason_ClientClosed:
		reasonText = "client closed the connection.";

		break;

	case EchoServer_StopReason_Error:
		//	terminationRequired = true;
		reasonText = "an error occurred. See previous log output for more information.";
		break;

	default:
		//	terminationRequired = true;
		reasonText = "unknown reason.";
		break;
	}

	// Restart server
	isNetworkStackReady = false;

	LogWebDebug("INFO: TCP server stopped: %s\n", reasonText);
}

webServer_ServerState *webServer_Start(EventLoop *el, in_addr_t ipAddr, uint16_t port,
									   int backlogSize,
									   void (*shutdownCallback)(webServer_StopReason))
{
	if(serverState==NULL) serverState = malloc(sizeof(*serverState));
	// Set EchoServer_ServerState state to unused values so it can be safely cleaned up if only a
	// subset of the resources are successfully allocated.
	serverState->el = el;
	serverState->listenFd = -1;
	serverState->clientFd = -1;
	serverState->listenFDReg=NULL;
	serverState->clientFDReg=NULL;

	serverState->txPayload = NULL;
	serverState->txPayloadSize = 0;
	serverState->txBytesSent = 0;
	serverState->shutdownCallback = shutdownCallback;

	int sockType = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	serverState->listenFd = OpenIpV4Socket(ipAddr, port, sockType);
	if (serverState->listenFd < 0)
	{
		ReportError("open socket");
		goto fail;
	}

	// Be notified asynchronously when a client connects.
	serverState->listenFDReg=EventLoop_RegisterIo(el, serverState->listenFd, EventLoop_Input,HandleListenEvent, NULL);

	int result = listen(serverState->listenFd, backlogSize);
	if (result != 0)
	{
		ReportError("listen");
		goto fail;
	}

	LogWebDebug("INFO: TCP server: Listening...\n");

	return serverState;

fail:
	webServer_ShutDown();
	return NULL;
}

void webServer_ShutDown(void)
{
	if (!serverState)
	{
		return;
	}

	CloseFdAndPrintError(serverState->clientFd, "clientFd");
	CloseFdAndPrintError(serverState->listenFd, "listenFd");

	free(serverState->txPayload);
}

void webServer_Restart(void)
{
	EventLoop * el = serverState->el;
	webServer_ShutDown();

	webServer_Start(el, localServerIpAddress.s_addr, LocalTcpServerPort,
								  serverBacklogSize, ServerStoppedHandler);
}

void CloseFdAndPrintError(int fd, const char *fdName)
{
    if (fd >= 0) {
        int result = close(fd);
        if (result != 0) {
            Log_Debug("ERROR: Could not close fd %s: %s (%d).\n", fdName, strerror(errno), errno);
        }
    }
}

static void HandleListenEvent(EventLoop *el, int fd, EventLoop_IoEvents events, void *context)
{
	int localFd = -1;

	do
	{
		// Create a new accepted socket to connect to the client.
		// The newly-accepted sockets should be opened in non-blocking mode, and use
		struct sockaddr in_addr;
		socklen_t sockLen = sizeof(in_addr);
		localFd = accept4(serverState->listenFd, &in_addr, &sockLen, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (localFd < 0)
		{
			ReportError("accept");
			break;
		}

		LogWebDebug("INFO: TCP server: request from client connection (fd %d).\n", localFd);

		// If already have a client, then close the newly-accepted socket.

		if (serverState->clientFd >= 0)
		{
			LogWebDebug("INFO: TCP server: Reject request fd %d as there is already one under processing.\n", localFd);
			break;
		}

		// Socket opened successfully, so transfer ownership to EchoServer_ServerState object.
		serverState->clientFd = localFd;
		localFd = -1;

		LaunchRead();
	} while (0);

	close(localFd);
}

static void LaunchRead(void)
{
	serverState->inLineSize = 0;
	if(serverState->clientFDReg!=NULL) {
		EventLoop_UnregisterIo(serverState->el, serverState->clientFDReg);
		serverState->clientFDReg=NULL;
	}
	serverState->clientFDReg= EventLoop_RegisterIo(serverState->el, serverState->clientFd, EventLoop_Input,HandleClientReadEvent, NULL);
}

static void HandleClientReadEvent(EventLoop *el, int fd, EventLoop_IoEvents events, void *context)
{
	if(serverState->clientFDReg!=NULL) {
		EventLoop_UnregisterIo(serverState->el, serverState->clientFDReg);
		serverState->clientFDReg=NULL;
	}

	// Continue until no immediately available input or until an error occurs.
	size_t maxChars = sizeof(serverState->input) - 1;
	uint8_t last;
	serverState->httpMethod = "unknown";
	uint8_t firstHeaderRow = 1;
	uint8_t postPayloadStart = 0;

	while (true)
	{
		// Read a single byte from the client and add it to the buffered line.
		uint8_t b;

		ssize_t bytesReadOneSysCall = recv(serverState->clientFd, &b, 1, /* flags */ 0);

		// If successfully read a single byte then process it.
		if (bytesReadOneSysCall == 1)
		{
			// If received newline then print received line to debug log.
			if (b == '\r' && postPayloadStart==0)
			{
				if(strlen(serverState->input)==0){//post payload starts after a complete empty line after http header
					postPayloadStart=1;
				}
				serverState->input[serverState->inLineSize] = '\0';
				serverState->inLineSize = 0;
			}
			else if (b == '\n' && last == '\r' && postPayloadStart==0)
			{
				if (firstHeaderRow)
				{
					firstHeaderRow = 0;
					char *pos = strstr(serverState->input, "GET ");
					if (pos != NULL)
						serverState->httpMethod = "GET";
					pos = strstr(serverState->input, "POST ");
					if (pos != NULL)
						serverState->httpMethod = "POST";

					if ((int)strcmp(serverState->httpMethod,"unknown") != 0 )
					{
						serverState->isHttp = 1;
						size_t begin = strlen(serverState->httpMethod)+1;
						size_t end = begin+1;

						if (serverState->input[begin] == '/')
						{
							while (serverState->input[end] != ' ')
								end++;
							strncpy(serverState->post, &serverState->input[begin], end - begin);
							serverState->post[end - begin] = '\0';
						}
					}
				}
				char* pos = strstr(serverState->input, "Content-Length:");
				if ( pos != NULL){
					char* contentLengthStr = malloc(10);
					uint8_t begin=strlen("Content-Length:")+1;
					strncpy(contentLengthStr, &serverState->input[begin], strlen(serverState->input) - begin);
					serverState->contentLength=(size_t)atoi(contentLengthStr);
					free(contentLengthStr);
				}

				// uncomment below line if you wanna see each header in log
				LogWebDebug("INFO: TCP server: Received \"%s\"\n", serverState->input);
			}

			// If new character is not printable then discard.
			

			// If new character would leave no space for NUL terminator then reset buffer.
			else if (serverState->inLineSize == maxChars)
			{
				LogWebDebug("INFO: TCP server: Input data overflow. Discarding %zu characters.\n",
							maxChars);
				serverState->input[0] = b;
				serverState->inLineSize = 1;
			}

			// Else append character to buffer.
			else
			{
				serverState->input[serverState->inLineSize] = b;
				++serverState->inLineSize;
			}

			last = b;
		}

		// If client has shut down restart the webServer.
		else if (bytesReadOneSysCall == 0)
		{
			LogWebDebug("INFO: TCP server: Client has closed connection, reset serverstate.\n");
			webServer_Restart();

			// StopServer(serverState, EchoServer_StopReason_ClientClosed);
			break;
		}

		else if (bytesReadOneSysCall == -1 && errno == EAGAIN)
		{
			if(postPayloadStart==1){
				//CHECK: why the inlinesize is shorter than contentlength?
				LogWebDebug("length:%d %d\n",serverState->inLineSize, serverState->contentLength);
			}

			LogWebDebug("method: %s   URI: %s   payload: %s\n", serverState->httpMethod, serverState->post, serverState->input);
			// Launch send after received hearder
			if (serverState->isHttp == 1)
				LaunchWrite();
			else{
				LogWebDebug("Unknown http method, skip...\n");
				webServer_Restart();
			}
				
			break;
		}

		// Another error occured so abort the program.
		else
		{
			ReportError("recv");
			LogWebDebug("TCP receive error, reset serverstate.\n");
			webServer_Restart();

			//  StopServer(serverState, EchoServer_StopReason_Error);
			break;
		}
	}
}

/// <summary>
///    special placeholder for replace loaded page position's string
/// </summary>
char *str_replace(char *body, size_t *bodylen, ...)
{

	char *placeholder = "<!!!---%s";
	size_t phlen = strlen(placeholder);

	int num = 0;
	char *insert = strstr(body, placeholder);
	while (insert != NULL)
	{
		++num;
		insert = strstr(insert + phlen, placeholder);
	}

	va_list valist;
	// cw_dbg va_start(valist, num);
	va_start(valist, bodylen);

	char *pos = NULL;
	for (int i = 0; i < num; i++)
	{
		const char *replace = va_arg(valist, const char *);

		size_t rlen = strlen(replace);

		size_t shift = rlen - phlen;
		body = realloc(body, *bodylen + shift);

		insert = strstr(body, placeholder);
		pos = body + *bodylen;
		if ((ssize_t)shift > 0)
		{
			while (pos-- != insert)
			{
				*(pos + shift) = *pos;
			}
		}
		else if ((ssize_t)shift < 0)
		{
			pos = insert + rlen - 1;
			char *end = body + *bodylen;
			while ((pos - shift) != end)
			{
				pos++;
				*pos = *(pos - shift);
			}
		}

		pos = insert + rlen - 1;

		while (rlen > 0)
		{
			*pos-- = replace[--rlen];
		}

		*bodylen += shift;
	}

	va_end(valist);

	return body;
	//*(body + (*bodylen - 1)) = '\0';
}



/// <summary>
///     Called when the website finished send for after process
/// </summary>


static void LaunchWrite(void)
{
	if((int)strcmp(serverState->httpMethod,"GET") == 0) LaunchWriteGET();
	else if((int)strcmp(serverState->httpMethod,"POST") == 0) LaunchWritePOST();
	else{
		return;
	}
	
	if(serverState->clientFDReg!=NULL) {
		EventLoop_UnregisterIo(serverState->el, serverState->clientFDReg);
		serverState->clientFDReg=NULL;
	}
	serverState->clientFDReg= EventLoop_RegisterIo(serverState->el, serverState->clientFd, EventLoop_Output,HandleClientWriteEvent, NULL);
}

static void LaunchWritePOST(void)
{
	char *header;
	if ((int)strcmp(serverState->post,"/uploadlog") == 0)
	{
		asprintf(&header, "HTTP/1.1 200 \015\012\
Connection:close\015\012\
\015\012");
		serverState->txPayloadSize = strlen(header);
		serverState->txPayload = (uint8_t *)header;
		serverState->txBytesSent = 0;
		// TODO: send the received log file content to iot hub....

		time_t now;
		time(&now);
		Cloud_Result result = Cloud_SendLogPayload(serverState->input, now);
		if (result != Cloud_Result_OK)
		{
			Log_Debug("WARNING: Could not send thermometer telemetry to cloud: %s\n",
					  CloudResultToString(result));
		}else{
			Log_Debug("Sent telemetry\n");
		}
	}
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

static void LaunchWriteGET(void)
{

	size_t begin = 0;
	size_t end = 0;
	while (serverState->post[++end] != '\0' && serverState->post[end] != '?'){}

	char *path = malloc(end);

	strncpy(path, &serverState->post[begin], end);
	path[end - begin] = '\0';
	// cw_dbg int update = 3;
	size_t bodylen = 0;

	// Set value for GET query
	char **get_name = NULL;
	char **get_value = NULL;
	size_t numofget = 0;

	if (serverState->post[end++] == '?')
	{
		begin = end;
		while (serverState->post[end++] != '\0')
		{
			if (serverState->post[end] == '=')
			{
				char name[end - begin + 1];

				strncpy(name, &serverState->post[begin], end - begin);
				name[end - begin] = '\0';
				begin = ++end;
				while (serverState->post[end] != '\0' && serverState->post[end] != '&')
					end++;
				char value[end - begin + 1];
				value[end - begin] = '\0';
				strncpy(value, &serverState->post[begin], end - begin);

				/// HTTP GET query

				++numofget;
				get_name = realloc(get_name, sizeof(char **) * numofget);
				get_value = realloc(get_value, sizeof(char **) * numofget);

				char *namePtr;
				asprintf(&namePtr, name);
				char *valuePtr;
				asprintf(&valuePtr, value);

				get_name[numofget - 1] = namePtr;
				get_value[numofget - 1] = valuePtr;

				begin = ++end;
			}
		}
	}

	char *timestr;
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	int hour = tm.tm_hour == 0 ? 12 : tm.tm_hour > 12 ? tm.tm_hour - 12
													  : tm.tm_hour;

	asprintf(&timestr, "Time: %d-%d-%d   %s %02d:%02d:%02d",
			 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour >= 12 ? "PM" : "AM", hour, tm.tm_min, tm.tm_sec);

	char *mime = "text/html";

	char *body;
	char *html;
	int result;
	int code;

	if (!strcmp(path, "/"))
	{
		// cw_dbg char* first = "index.htm";
		path = "/index.htm";
	}

	const char delim[2] = ".";

	char *buf;
	char *filetype;
	asprintf(&buf, path);

	filetype = strtok(buf, delim);

	while (true)
	{
		char *next = strtok(NULL, ".");
		if (next != NULL)
		{

			filetype = next;
		}
		else
			break;
	}

	size_t namelen = strlen(path) - strlen(filetype) - 2;
	char *filename = malloc(namelen);
	for (int i = 0; i < namelen; i++)
	{
		filename[i] = path[i + 1];
	}
	filename[namelen] = '\0';

	// First page, simple show weather data

	int mimetype = MIME_NONE;

	if (!strcmp(filetype, "htm") || !strcmp(filetype, "html"))
	{
		mimetype = MIME_TEXT;
	}
	else if (!strcmp(filetype, "txt"))
	{
		mimetype = MIME_TEXT;
		mime = "text/plain";
	}
	else if (!strcmp(filetype, "json"))
	{
		mimetype = MIME_TEXT;
		mime = "application/json";
	}
	else if (!strcmp(filetype, "js"))
	{
		mimetype = MIME_TEXT;
		mime = "text/javascript";
	}
	else if (!strcmp(filetype, "ico"))
	{
		mimetype = MIME_DATA;
		mime = "image/x-icon";
	}
	else if (!strcmp(filetype, "jpg") || !strcmp(filetype, "jpeg"))
	{
		mimetype = MIME_DATA;
		mime = "image/jpeg";
	}
	else if (!strcmp(filetype, "png"))
	{
		mimetype = MIME_DATA;
		mime = "image/png";
	}
	else if (!strcmp(filetype, "gif"))
	{
		mimetype = MIME_DATA;
		mime = "image/gif";
	}
	else if (!strcmp(filetype, "bmp"))
	{
		mimetype = MIME_DATA;
		mime = "image/bmp";
	}
	else if (!strcmp(filetype, "webp"))
	{
		mimetype = MIME_DATA;
		mime = "image/webp";
	}
	else if (!strcmp(filetype, "pdf"))
	{
		mimetype = MIME_DATA;
		mime = "application/pdf";
	}
	else if (!strcmp(filetype, "bz"))
	{
		mimetype = MIME_DATA;
		mime = "application/x-bzip";
	}
	else if (!strcmp(filetype, "bz2"))
	{
		mimetype = MIME_DATA;
		mime = "application/x-bzip2";
	}
	else if (!strcmp(filetype, "rar"))
	{
		mimetype = MIME_DATA;
		mime = "application/x-rar-compressed";
	}
	else if (!strcmp(filetype, "zip"))
	{
		mimetype = MIME_DATA;
		mime = "application/zip";
	}
	else if (!strcmp(filetype, "7z"))
	{
		mimetype = MIME_DATA;
		mime = "application/x-7z-compressed";
	}

	bool nofile = true;

	if (mimetype != MIME_NONE)
	{
		char *filepath = ((char *)path) + 1;

		int fileFD = Storage_OpenFileInImagePackage(filepath);
		if (fileFD < 0)
		{
			Log_Debug("ERROR: Storage Error: errno=%d (%s)\n", errno,
					  strerror(errno));
		}
		else
		{
			nofile = false;

			char buf[FILEREADBUFFERSIZE];

			char *data = NULL;
			size_t size = 0;
			size_t total = 0;
			do
			{
				size = (size_t)(read(fileFD, buf, FILEREADBUFFERSIZE));
				if (size <= 0)
					break;

				data = (char *)realloc(data, (total + size) * sizeof(char));

				for (size_t i = 0; i < size; i++)
					data[i + total] = buf[i];

				total += size;

			} while (true);

			// cw_dbg free(buf);

			if (mimetype == MIME_TEXT)
			{
				data = (char *)realloc(data, ((total) + 1) * sizeof(char));
				data[total] = '\0';
				total += 1;
			}

			body = data;

			bodylen = total;
		}
	}

	if (nofile)
	{
		code = 404;
		result = asprintf(&body, "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n\
			<html>\n\
			<head>\n\
			 <meta http-equiv=\"Content-type\" content=\"text/html;charset=UTF-8\">\n\
			<title>Weather </title>\n\
			 </head>\n\
			  <body >\n\
				<h4>404 Not found</h4></body></html><br>azsphere webInterface",
						  localServerIpAddress.s_addr, LocalTcpServerPort);

		bodylen = strlen(body);
		// cw_dbg mimetype == MIME_TEXT;
		mimetype = MIME_TEXT;
		mime = "text/html";

		if (result == -1)
		{
			ReportError("asprintf");
			StopServer(EchoServer_StopReason_Error);
			return;
		}
	}
	else
	{
		code = 200;
	}

	// header
	char *status;
	if (code == 200)
		asprintf(&status, "%d %s", code, "Ok");
	else
		asprintf(&status, "%d %s", code, "Not found");
	char *header;
	result = asprintf(&header, "HTTP/1.1 %s \015\012\
Server: AzSphere\015\012\
Cache-Control: private, max-age=0\015\012\
Content-Length:%d\015\012\
Content-Type: %s\015\012\
Connection:close\015\012\
\015\012",
					  status, bodylen, mime);

	// cw_dbg int headerlen = strlen(header);
	size_t headerlen = strlen(header);

	if (mimetype == MIME_TEXT)
	{

		asprintf(&html, "%s%s", header, body);
	}
	else if (mimetype == MIME_DATA)
	{

		html = realloc(header, sizeof(char) * (headerlen + bodylen));
		for (size_t i = 0; i < bodylen; i++)
			html[headerlen + i] = body[i];
	}

	// free(body);
	// free(status);

	serverState->txPayloadSize = bodylen + headerlen;
	serverState->txPayload = (uint8_t *)html;
	serverState->txBytesSent = 0;
}

static void HandleClientWriteEvent(EventLoop *el, int fd, EventLoop_IoEvents events, void *context)
{
	if(serverState->clientFDReg!=NULL) {
		EventLoop_UnregisterIo(serverState->el, serverState->clientFDReg);
		serverState->clientFDReg=NULL;
	}

	// Continue until have written entire response, error occurs, or OS TX buffer is full.
	while (serverState->txBytesSent < serverState->txPayloadSize)
	{
		size_t remainingBytes = serverState->txPayloadSize - serverState->txBytesSent;
		const uint8_t *data = &serverState->txPayload[serverState->txBytesSent];
		ssize_t bytesSentOneSysCall =
			send(serverState->clientFd, data, remainingBytes, /* flags */ 0);

		// If successfully sent data then stay in loop and try to send more data.
		if (bytesSentOneSysCall > 0)
		{
			serverState->txBytesSent += (size_t)bytesSentOneSysCall;
		}

		else if (bytesSentOneSysCall < 0 && errno == EAGAIN)
		{
			serverState->clientFDReg= EventLoop_RegisterIo(serverState->el, serverState->clientFd, EventLoop_Output,HandleClientWriteEvent, NULL);
			return;
		}

		// Another error occurred so terminate the program.
		else
		{
			ReportError("send");
			// StopServer(serverState, EchoServer_StopReason_Error);
			LogWebDebug("error in TCP sending, reset serverstate.\n");
			webServer_Restart();

			return;
		}
	}

	// If reached here then successfully sent entire payload so clean up and read next line from
	// client.
	free(serverState->txPayload);
	LogWebDebug("Finish client request fd %d.\n",serverState->clientFd);
           
    // Socket opened successfully, so transfer ownership to EchoServer_ServerState object.
	serverState->txPayload = NULL;
	
	// Restart for next process
	// LogWebDebug("After http write event, reset serverstate.\n");
	webServer_Restart();
}

static int OpenIpV4Socket(in_addr_t ipAddr, uint16_t port, int sockType)
{
	int localFd = -1;
	int retFd = -1;

	do
	{
		// Create a TCP / IPv4 socket. This will form the listen socket.
		localFd = socket(AF_INET, sockType, /* protocol */ 0);
		if (localFd < 0)
		{
			ReportError("socket");
			break;
		}

		// Enable rebinding soon after a socket has been closed.
		int enableReuseAddr = 1;
		int r = setsockopt(localFd, SOL_SOCKET, SO_REUSEADDR, &enableReuseAddr,
						   sizeof(enableReuseAddr));
		if (r != 0)
		{
			ReportError("setsockopt/SO_REUSEADDR");
			break;
		}

		// Bind to a well-known IP address.
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = ipAddr;
		addr.sin_port = htons(port);

		r = bind(localFd, (const struct sockaddr *)&addr, sizeof(addr));
		if (r != 0)
		{
			ReportError("bind");
			break;
		}

		// Port opened successfully.
		retFd = localFd;
		localFd = -1;
	} while (0);

	close(localFd);

	return retFd;
}

static void ReportError(const char *desc)
{
	LogWebDebug("ERROR: TCP server: \"%s\", errno=%d (%s)\n", desc, errno, strerror(errno));
}

static void StopServer(webServer_StopReason reason)
{
	// Stop listening for incoming connections.
	if (serverState->listenFd != -1)
	{
		EventLoop_UnregisterIo(serverState->el, serverState->listenFDReg);
	}

	serverState->shutdownCallback(reason);
}

int LogWebDebug(const char *fmt, ...)
{

	va_list argptr;
	va_start(argptr, fmt);

	Log_DebugVarArgs(fmt, argptr);

	if (!isWebDebug)
		return 0;

	char buffer[256];

	int total = vsprintf(buffer, fmt, argptr);

	if (total == 0)
		return 0;

	if (buffer[total - 1] != '\n')
	{
		buffer[total++] = '\n';
		buffer[total] = '\0';
	}

	for (int i = 0; i < total; i++)
	{
		if (buffer[i] == '<')
		{
			// replace to "(" if not enough buffer
			if (total + 3 > 256)
			{
				buffer[i] = '(';
				continue;
			}
			// otherwise replace html escape
			for (int j = total; j > i + 3; j--)
				buffer[j] = buffer[j - 3];
			buffer[i] = '&';
			buffer[i + 1] = 'l';
			buffer[i + 2] = 't';
			buffer[i + 3] = ';';
			total += 3;
		}
		else if (buffer[i] == '>')
		{
			// replace to ")" if not enough buffer
			if (total + 3 > 256)
			{
				buffer[i] = ')';
				continue;
			}
			// otherwise replace html escape
			for (int j = total; j > i + 3; j--)
				buffer[j] = buffer[j - 3];
			buffer[i] = '&';
			buffer[i + 1] = 'g';
			buffer[i + 2] = 't';
			buffer[i + 3] = ';';
			total += 3;
		}
		else if (buffer[i] == '&')
		{
			// replace to "A" if not enough buffer
			if (total + 4 > 256)
			{
				buffer[i] = 'A';
				continue;
			}
			// otherwise replace html escape
			for (int j = total; j > i + 4; j--)
				buffer[j] = buffer[j - 4];
			buffer[i] = '&';
			buffer[i + 1] = 'a';
			buffer[i + 2] = 'm';
			buffer[i + 3] = 'p';
			buffer[i + 4] = ';';
			total += 4;
		}
	}

	weblogBuffer_n += total;

	while (weblogBuffer_n > MAX_WEBLOG)
	{
		// find first next line char
		char *firstnextline = strchr(weblogBuffer, '\n');
		if (firstnextline == NULL)
		{
			weblogBuffer_n = 0;
			break;
		}

		// shift content to begin

		int i = 0;
		do
		{
			weblogBuffer[i++] = *++firstnextline;
		} while (*(firstnextline) != '\0');
		weblogBuffer_n = i + total - 1;
	}

	int j = 0;
	int i = weblogBuffer_n - total;
	if (i > 0)
		i--;

	for (; i < weblogBuffer_n; i++)
		weblogBuffer[i] = buffer[j++];

	return 0;
}