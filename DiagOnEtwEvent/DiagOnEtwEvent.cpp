#include "DiagOnEtwEvent.h"
#include "Ktrace.h"

int wmain(int argc, LPWSTR argv[])
{
    if (argc < 3 || argc > 4)
    {
        wprintf(L"ERROR: Wrong number of arguments passed (at minimum, the first 2 are needed). Arguments needed are:\n");
        wprintf(L"\tArg1 - the name of the process including .exe in the name.\n");
        wprintf(L"\tArg2 - the name of the module (DLL) including .dll in the name.\n");
        wprintf(L"\tArg3 [opt] - the action type to perform - valid values are DMP or TTD - default is TTD.\n");

        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    }
    else if (argc == 4 &&
        wcscmp(TTD_ACTION, argv[3]) != 0 &&
        wcscmp(DBG_ACTION, argv[3]) != 0
        )
    {
        wprintf(L"ERROR: Wrong value passed for the 3rd argument - available values are TTD or DBG - default if not passed is TTD.\n");

        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    }

    HRESULT hr = ERROR_SUCCESS;
    DWORD dwThreadIdKernel = 0;
    HANDLE kernelTraceThread = NULL;
    HANDLE stopEvent;
    KernelTraceSession* kernelTraceSession = NULL;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    TOKEN_PRIVILEGES tkp;
    WCHAR processName[MAX_PATH];
    WCHAR moduleName[MAX_PATH];
    WCHAR actionType[OPTION_LENGTH + 1];

    StringCchCopy(processName, MAX_PATH, argv[1]);
    StringCchCopy(moduleName, MAX_PATH, argv[2]);

    if (argc == 4)
    {
        StringCchCopy(actionType, OPTION_LENGTH + 1, argv[3]);
    }
    else
    {
        StringCchCopy(actionType, OPTION_LENGTH + 1, TTD_ACTION);
    }

    wprintf(L"Starting to monitor for Process: %s and Module: %s and Action: %s\n", processName, moduleName, actionType);
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        hr = GetLastError();
        Win32ErrorToString(L"ERROR: Cannot open process Token", hr);
        goto cleanup;
    }
    
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize))
    {
        if (!elevation.TokenIsElevated)
        {
            hr = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
            Win32ErrorToString(L"ERROR: This process must be executed from an elevated prompt", hr);
            goto cleanup;
        }
    }
    else
    {
        hr = GetLastError();
        Win32ErrorToString(L"ERROR: Failed to get token information", hr);
        goto cleanup;
    }
    
    memset(&tkp, 0, sizeof(tkp));
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, SE_SYSTEM_PROFILE_NAME, &tkp.Privileges[0].Luid))
    {
        hr = GetLastError();
        Win32ErrorToString(L"ERROR: Failed LookupPrivilegeValue", hr);
        goto cleanup;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
    {
        hr = GetLastError();
        Win32ErrorToString(L"ERROR: Failed AdjustTokenPrivileges", hr);
        goto cleanup;
    }

    stopEvent = CreateEvent(NULL, true, false, NULL);
    if (stopEvent == NULL)
    {
        hr = GetLastError();
        Win32ErrorToString(L"ERROR: Failed to create event", hr);
        goto cleanup;
    }

    kernelTraceSession = KernelTraceInstance(processName, moduleName, actionType, stopEvent);
    if (kernelTraceSession == NULL)
    {
        hr = E_FAIL;
        Win32ErrorToString(L"ERROR: Could not create the trace", hr);
        goto cleanup;
    }

    dwThreadIdKernel = 0;
    kernelTraceThread = CreateThread(NULL, 0, KernelTraceThreadFunc, kernelTraceSession, 0, &dwThreadIdKernel);

    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, true))
    {
        hr = GetLastError();
        Win32ErrorToString(L"ERROR: Could not set control handler", hr);
        goto cleanup;
    }

    wprintf(L"Press Ctrl+C to stop the program.\n");

    if (WaitForSingleObject(stopEvent, INFINITE) == WAIT_OBJECT_0)
    {
        wprintf(L"Stop event was set ... stopping.\n");
    }
    else
    {
        hr = GetLastError();
        Win32ErrorToString(L"ERROR: WaitForSingleObject failed", hr);
    }


cleanup:

    if (kernelTraceSession)
    {
        kernelTraceSession->Stop();
    }

    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }

    if (kernelTraceThread)
    {
        TerminateThread(kernelTraceThread, NULL);
        kernelTraceThread = NULL;
    }

    return hr;
}

static DWORD WINAPI KernelTraceThreadFunc(LPVOID lpParam)
{
    KernelTraceSession* kernelTraceSession = (KernelTraceSession*)lpParam;
    kernelTraceSession->Run();

    return 0;
}

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