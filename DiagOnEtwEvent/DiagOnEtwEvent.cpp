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

TCHAR WaitPressAnyKey(const TCHAR* prompt = NULL)
{
    TCHAR  ch;
    DWORD  mode;
    DWORD  count;
    HANDLE hstdin = GetStdHandle(STD_INPUT_HANDLE);

    // Prompt the user
    if (prompt == NULL)
    {
        prompt = TEXT("Press any key to continue...");
    }

    WriteConsole(
        GetStdHandle(STD_OUTPUT_HANDLE),
        prompt,
        lstrlen(prompt),
        &count,
        NULL
    );

    // Switch to raw mode
    GetConsoleMode(hstdin, &mode);
    SetConsoleMode(hstdin, 0);

    // Wait for the user's response
    WaitForSingleObject(hstdin, INFINITE);

    // Read the (single) key pressed
    ReadConsole(hstdin, &ch, 1, &count, NULL);

    // Restore the console to its previous state
    SetConsoleMode(hstdin, mode);

    // Return the key code
    return ch;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 4)
    {
        wprintf(L"Wrong number of arguments passed. Arguments needed are:\n");
        wprintf(L"\tArg1 - the name of the process including .exe in the name.\n");
        wprintf(L"\tArg2 - the name of the module (DLL) including .dll in the name.\n");
        wprintf(L"\tArg3 - the action type to perform - valid values are DMP or TTD.\n");

        return -1;
    }

    LPWSTR processName = (LPWSTR)malloc(sizeof(WCHAR) * MAX_PATH);
    LPWSTR moduleName = (LPWSTR)malloc(sizeof(WCHAR) * MAX_PATH);
    LPWSTR actionType = (LPWSTR)malloc(sizeof(WCHAR) * 3);

    StrCpy(processName, argv[1]);
    StrCpy(moduleName, argv[2]);
    StrCpy(actionType, argv[3]);

    wprintf(L"Starting to monitor for Process: %s and Module: %s and Action: %s\n", processName, moduleName, actionType);

    HANDLE hToken = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        TOKEN_PRIVILEGES tkp;
        memset(&tkp, 0, sizeof(tkp));
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(NULL, SE_SYSTEM_PROFILE_NAME, &tkp.Privileges[0].Luid);

        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
        {
            if (!Elevation.TokenIsElevated)
            {
                wprintf(L"ERROR: This process must be executed from an elevated prompt.");
                return -1;
            }
        }

        if (hToken)
        {
            ::CloseHandle(hToken);
        }
    }
    else
    {
        wprintf(L"ERROR: Cannot open current process: 0x%x", HRESULT_FROM_WIN32(GetLastError()));
        return -1;
    }

    // create instances of our trace session classes.  The xxInstance() calls
    // perform some setup:
    //     StartTrace(), EnableTraceEx2(), OpenTrace()
    // If there are failures along the way, NULL pointer is returned.

    KernelTraceSession* kernelTraceSession = KernelTraceInstance(processName, moduleName, actionType);

    if (!kernelTraceSession) {
        wprintf(L"Error: could not create a trace. kernel:0x%p\n", kernelTraceSession);
        return -1;
    }

    DWORD dwThreadIdKernel = 0;
    HANDLE kernelTraceThread = CreateThread(NULL, 0, KernelTraceThreadFunc, kernelTraceSession, 0, &dwThreadIdKernel);

    WaitPressAnyKey(L"Press any key to stop ...\n");

    // set a flag in each of our Trace Session classes, so that next time
    // BufferCallback() are called, they return false.  This will instruct ETW
    // to stop sending events.

    kernelTraceSession->Stop();

    // Give it a second...

    Sleep(1000);

    // Finally, terminate the thread

    TerminateThread(kernelTraceThread, 0);

    return 0;
}