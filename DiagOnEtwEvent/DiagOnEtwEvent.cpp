#include "DiagOnEtwEvent.h"
#include "Ktrace.h"

//-------------------------------------------------------------------------
// Function for kernel trace thread.  It will call Run(), which
// calls ProcessTrace() Windows API call.
//-------------------------------------------------------------------------
static DWORD WINAPI KernelTraceThreadFunc(LPVOID lpParam)
{
    KernelTraceSession* kernelTraceSession = (KernelTraceSession*)lpParam;
    kernelTraceSession->Run();

    return 0;
}

//-------------------------------------------------------------------------
// Function for handling signal events.  It will signal the stop event,
// which stops everything and ends to program.
//-------------------------------------------------------------------------

bool WINAPI ConsoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT ||
        signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_LOGOFF_EVENT ||
        signal == CTRL_SHUTDOWN_EVENT
        )
    {
        SetEvent(GetKernelTraceInstance()->GetStopEvent());
    }

    return true;
}

int wmain(int argc, LPWSTR argv[])
{
    if (argc < 3 || argc > 4)
    {
        wprintf(L"ERROR: Wrong number of arguments passed (at minimum, the first 2 are needed). Arguments needed are:\n");
        wprintf(L"\tArg1 - the name of the process including .exe in the name.\n");
        wprintf(L"\tArg2 - the name of the module (DLL) including .dll in the name.\n");
        wprintf(L"\tArg3 [opt] - the action type to perform - valid values are DMP or TTD - default is TTD.\n");

        return -1;
    }

    DWORD dwThreadIdKernel = 0;
    HANDLE kernelTraceThread = NULL;
    HANDLE stopEvent;
    KernelTraceSession* kernelTraceSession = NULL;

    LPWSTR actionType = (LPWSTR)malloc(sizeof(WCHAR) * 3);
    StrCpy(actionType, TTD_ACTION);

    if (argc == 4 &&
        wcscmp(TTD_ACTION, argv[3]) != 0 &&
        wcscmp(DBG_ACTION, argv[3]) != 0
        )
    {
        wprintf(L"ERROR: Wrong value passed for the 3rd argument - available values are TTD or DBG - default if not passed is TTD.\n");

        return -1;
    }
    else
    {
        StrCpy(actionType, argv[3]);
    }

    LPWSTR processName = (LPWSTR)malloc(sizeof(WCHAR) * MAX_PATH);
    LPWSTR moduleName = (LPWSTR)malloc(sizeof(WCHAR) * MAX_PATH);
    StrCpy(processName, argv[1]);
    StrCpy(moduleName, argv[2]);

    wprintf(L"Starting to monitor for Process: %s and Module: %s and Action: %s\n", processName, moduleName, actionType);

    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize))
        {
            if (!elevation.TokenIsElevated)
            {
                wprintf(L"ERROR: This process must be executed from an elevated prompt.\n");
                goto cleanup;
            }
        }
        else
        {
            wprintf(L"ERROR: Failed to get token information with error 0x%x.\n", GetLastError());
            goto cleanup;
        }

        TOKEN_PRIVILEGES tkp;
        memset(&tkp, 0, sizeof(tkp));
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!LookupPrivilegeValue(NULL, SE_SYSTEM_PROFILE_NAME, &tkp.Privileges[0].Luid))
        {
            wprintf(L"ERROR: Failed LookupPrivilegeValue with error 0x%x.\n", GetLastError());
            goto cleanup;
        }

        if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
        {
            wprintf(L"ERROR: Failed AdjustTokenPrivileges with error 0x%x", GetLastError());
            goto cleanup;
        }
    }
    else
    {
        wprintf(L"ERROR: Cannot open current process: 0x%x", HRESULT_FROM_WIN32(GetLastError()));
        goto cleanup;
    }

    stopEvent = CreateEvent(NULL, true, false, NULL);
    if (stopEvent == NULL)
    {
        wprintf(L"ERROR: Failed to create event with error 0x%x", HRESULT_FROM_WIN32(GetLastError()));
        goto cleanup;
    }

    kernelTraceSession = KernelTraceInstance(processName, moduleName, actionType, stopEvent);

    if (kernelTraceSession == NULL) {
        wprintf(L"Error: could not create a trace. kernel:0x%p\n", kernelTraceSession);
        goto cleanup;
    }

    dwThreadIdKernel = 0;
    kernelTraceThread = CreateThread(NULL, 0, KernelTraceThreadFunc, kernelTraceSession, 0, &dwThreadIdKernel);

    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, true))
    {
        printf("ERROR: Could not set control handler with error 0x%x\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"Press Ctrl+C to stop the program.\n");

    switch (WaitForSingleObject(stopEvent, INFINITE))
    {
    case WAIT_OBJECT_0:
        wprintf(L"Stop event was set ... stopping.\n");
        break;

    default:
        wprintf(L"ERROR: WaitForSingleObject failed 0x%x\n", GetLastError());
        break;
    }

cleanup:

    if (kernelTraceSession)
    {
        kernelTraceSession->Stop();

        // wait 1 second for the processing thread
        Sleep(1000);
    }

    if (hToken)
    {
        CloseHandle(hToken);
    }

    if (kernelTraceThread)
    {
        TerminateThread(kernelTraceThread, NULL);
        kernelTraceThread = NULL;
    }

    return 0;
}