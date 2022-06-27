/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#pragma once

/// <summary>
/// Exit codes for this application. These are used for the
/// application exit code. They must all be between zero and 255,
/// where zero is reserved for successful termination.
/// </summary>
typedef enum {
    ExitCode_Success = 0,

    ExitCode_TermHandler_SigTerm = 1,

    ExitCode_Main_EventLoopFail = 2,

    ExitCode_ButtonTimer_Consume = 3,

    ExitCode_AzureIoTConnectionTimer_Consume = 4,

    ExitCode_Init_EventLoop = 5,
    ExitCode_Init_Button = 6,
    /* ExitCode 7 no longer used */
    ExitCode_Init_Led = 8,
    ExitCode_Init_ButtonPollTimer = 9,
    ExitCode_Init_AzureIoTConnectionTimer = 10,

    ExitCode_IsButtonPressed_GetValue = 11,

    /* ExitCode 12 no longer used */

    ExitCode_Validate_ScopeId = 13,
    ExitCode_Validate_Hostname = 14,
    ExitCode_Validate_IoTEdgeCAPath = 15,

    ExitCode_IsNetworkingReady_Failed = 16,

    ExitCode_IoTEdgeRootCa_Open_Failed = 17,
    ExitCode_IoTEdgeRootCa_LSeek_Failed = 18,
    ExitCode_IoTEdgeRootCa_FileSize_Invalid = 19,
    ExitCode_IoTEdgeRootCa_FileSize_TooLarge = 20,
    ExitCode_IoTEdgeRootCa_FileRead_Failed = 21,

    ExitCode_PayloadSize_TooLarge = 22,

    ExitCode_Init_TelemetryTimer = 23,
    ExitCode_TelemetryTimer_Consume = 24,

    ExitCode_Validate_ConnectionConfig = 25,
    ExitCode_Connection_CreateTimer = 26,
    ExitCode_Connection_TimerStart = 27,
    ExitCode_Connection_TimerConsume = 28,
    ExitCode_Connection_InitializeClient = 29,

    ExitCode_Init_AzureIoTDoWorkTimer = 30,
    ExitCode_AzureIoTDoWorkTimer_Consume = 31,

    /* _PrivNetServ_ */
    ExitCode_WebServer_Start = 32,
    ExitCode_StoppedHandler_Stopped = 33,
    ExitCode_CheckStatus_SetInterfaceState = 34,
    ExitCode_CheckStatus_GetInterfaceCount = 35,
    ExitCode_CheckStatus_GetInterfaceConnectionStatus = 36,
    ExitCode_ConfigureStaticIp_IpConfigApply = 37,
    ExitCode_StartSntpServer_StartSntp = 38,
    ExitCode_StartDhcpServer_StartDhcp = 39,
    ExitCode_TimerHandler_Consume = 40,
    ExitCode_InitLaunch_EventLoop = 41,
    ExitCode_InitLaunch_Timer = 42,
//    ExitCode_Main_EventLoopFail = 42,
    ExitCode_EchoStart_Listen = 43,
    ExitCode_OpenIpV4_Socket = 44,
    ExitCode_OpenIpV4_SetSockOpt = 45,
    ExitCode_OpenIpV4_Bind = 46,

    /* Util Error Code */
    ExitCode_Util_Ptr_Error = 33,
    ExitCode_Util_Size_Error = 34
} ExitCode;

/// <summary>
/// Callback type for a function to be invoked when a fatal error with exit code needs to be raised.
/// </summary>
/// <param name="exitCode">Exit code representing the failure.</param>
typedef void (*ExitCode_CallbackType)(ExitCode exitCode);
