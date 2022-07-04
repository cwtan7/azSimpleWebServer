/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

#include <applibs/log.h>

#include "options.h"
#include "exitcodes.h"
#include "connection.h"
#include "privatenetserv.h"

static ExitCode ValidateUserConfiguration(void);

// Usage text for command line arguments in application manifest.
static const char *cmdLineArgsUsageText =
    "The command line arguments for the application shoud be set in app_manifest.json as below:\n"
    "\" CmdArgs \": [\"--ScopeID\", \"<scope_id>\", "
                    "\"--NetworkIF\", \"<net_if_type>\", "          // [Mandatory] wlan0 | eth0
                    "\"--IPMode\", \"<ip_mode>\", "                 // [Mandatory]: static | dynamic
                    "\"--IPPort\", \"<ip_port>\", "                 // [Mandatory]: IP Port #
                    "\"--IPAddr\", \"<ip_static_address>\", "       // [Optional]: Only require for Static IP Mode
                    "\"--IPSubnetMask\", \"<ip_subnet_mask>\", "    // [Optional]: Only require for Static IP Mode
                    "\"--IPGwAddr\", \"<ip_gw_address>\"]\n";       // [Optional]: Only require for Static IP Mode

ExitCode Options_ParseArgs(int argc, char *argv[])
{
    int option = 0;
    static const struct option cmdLineOptions[] = {
        {.name = "ScopeID", .has_arg = required_argument, .flag = NULL, .val = 's'},
        {.name = "NetworkIF", .has_arg = required_argument, .flag = NULL, .val = 'i'},
        {.name = "IPMode", .has_arg = required_argument, .flag = NULL, .val = 'm'},
        {.name = "IPAddr", .has_arg = required_argument, .flag = NULL, .val = 'a'},
        {.name = "IPSubnetMask", .has_arg = required_argument, .flag = NULL, .val = 'n'},
        {.name = "IPGwAddr", .has_arg = required_argument, .flag = NULL, .val = 'g'},
        {.name = "IPPort", .has_arg = required_argument, .flag = NULL, .val = 'p'},
        {.name = NULL, .has_arg = 0, .flag = NULL, .val = 0}};

    // Loop over all of the options.
    while ((option = getopt_long(argc, argv, "s:i:m:a:n:g:p:", cmdLineOptions, NULL)) != -1) {
        // Check if arguments are missing. Every option requires an argument.
        if (optarg != NULL && optarg[0] == '-') 
        {
            Log_Debug("WARNING: Option %c requires an argument\n", option);
            continue;
        }

        switch (option) 
        {
            case 's':
                Log_Debug("ScopeID: %s\n", optarg);
                Connection_SetDPSScopeId(optarg);
                break;
            case 'i':
                Log_Debug("NetworkIF: %s\n", optarg);
                SetNetworkInterface(optarg);
                break;
            case 'm':
                Log_Debug("IPMode: %s\n", optarg);
                SetIPMode(optarg);
                break;
            case 'a':
                Log_Debug("IPAddr: %s\n", optarg);
                SetIPAddress(optarg);
                break;
            case 'n':
                Log_Debug("IPSubnetMask: %s\n", optarg);
                SetIPSubnetMask(optarg);
                break;
            case 'g':
                Log_Debug("IPGwAddr: %s\n", optarg);
                SetGwAddress(optarg);
                break;
            case 'p':
                Log_Debug("IPPort: %s\n", optarg);
                SetIPServerPort(optarg);
                break;
            
            default:
                // Unknown options are ignored.
                break;
        }
    }

    return ValidateUserConfiguration();
}

static ExitCode ValidateUserConfiguration(void)
{
    ExitCode validationExitCode = ExitCode_Success;

    const char *scopeId = Connection_GetDPSScopeId();
    
    if (scopeId == NULL)
    {
        validationExitCode = ExitCode_Validate_ScopeId;
    } else
    {
        Log_Debug("Using DPS Connection: Azure IoT DPS Scope ID %s\n", scopeId);
    }

    if (validationExitCode != ExitCode_Success)
    {
        Log_Debug(cmdLineArgsUsageText);
    }

    return validationExitCode;
}
