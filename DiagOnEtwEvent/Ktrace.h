#pragma once

#define INITGUID

#include <guiddef.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <psapi.h>
#include <shlwapi.h>
#include <DbgHelp.h>
#include <time.h>
#include <strsafe.h>

#include <vector>
#include <string>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment (lib, "dbghelp.lib")

constexpr LPCWSTR ACTION_TTD = L"TTD";
constexpr LPCWSTR ACTION_DMP = L"DMP";
constexpr LPCWSTR TTD_REGISTRY_PATH = L".DEFAULT\\Software\\Microsoft\\TTT";
constexpr LPCWSTR TTD_PROCESS_NAME = L"TTTracer.exe";
constexpr LPCWSTR TTD_REGISTRY_EULA_KEY = L"EULASigned";
constexpr LPCWSTR TTD_DEFAULT_CMDLINE = L"-dumpFull -children -attach ";
constexpr LPCWSTR NT_LOGGER_SESSION_NAME = L"NT Kernel Logger"; // DO NOT CHANGE - must be this value

enum Image_Load
{
    ImageBase,
    ImageSize,
    ProcessId,
    ImageChecksum,
    TimeDateStamp,
    SignatureLevel,
    SignatureType,
    Reserved0,
    DefaultBase,
    Reserved1,
    Reserved2,
    Reserved3,
    Reserved4,
    FileName
};

class KernelTraceSession
{
public:
    /*
     * Run()
     * Will block until Stop() is called, so this should be called from a dedicated thread.
     */
    virtual void Run() = 0;

    /**
     * Sets a flag, so that next time ETW calls our internal BufferCallback() we will
     * return FALSE.
     */
    virtual void Stop() = 0;

};

/**
 * KernelTraceSession is a singleton.  Will return existing instance or
 * create a new one before return.
 *
 * Returns NULL if setup failed, instance otherwise.
 */
KernelTraceSession* KernelTraceInstance(LPWSTR, LPWSTR, LPWSTR, HANDLE);

class KernelTraceSessionImpl : public KernelTraceSession
{
public:
    /*
     * constructor
     */
    KernelTraceSessionImpl(LPWSTR processName, LPWSTR moduleName, LPWSTR actionType, HANDLE stopEvent) : 
        m_stopFlag(false),
        m_userPropLen(0),
        m_startTraceHandle(0L),
        m_processName(processName),
        m_moduleName(moduleName),
        m_actionType(actionType),
        m_stopEvent(stopEvent),
        m_petp(NULL)
    {}

    ~KernelTraceSessionImpl()
    {
        if (m_processName)
        {
            free(m_processName);
            m_processName = NULL;
        }

        if (m_moduleName)
        {
            free(m_moduleName);
            m_moduleName = NULL;
        }

        if (m_actionType)
        {
            free(m_actionType);
            m_actionType = NULL;
        }

        if (m_startTraceHandle)
        {
            HRESULT hr = ::ControlTrace(m_startTraceHandle, NT_LOGGER_SESSION_NAME, m_petp, EVENT_TRACE_CONTROL_STOP);

            if (hr != ERROR_SUCCESS)
            {
                printf("ControlTrace returned %ul\n", hr);
            }
        }

        if (m_stopEvent)
        {
            CloseHandle(m_stopEvent);
        }
    }

    virtual void Run();

    virtual void Stop()
    {
        m_stopFlag = true;

        if (m_stopEvent != NULL)
        {
            SetEvent(m_stopEvent);
        }
    }

    bool Setup();
    void OnRecordEvent(PEVENT_RECORD);
    bool OnBuffer(PEVENT_TRACE_LOGFILE);
    bool StartTraceSession(std::wstring, DWORD, TRACEHANDLE&);

private:

    DWORD GetUserPropLen(PEVENT_RECORD);

    bool m_stopFlag;
    TRACEHANDLE  m_startTraceHandle;
    int m_userPropLen;
    LPWSTR m_processName;
    LPWSTR m_moduleName;
    LPWSTR m_actionType;
    PEVENT_TRACE_PROPERTIES m_petp;
    HANDLE m_stopEvent;
};