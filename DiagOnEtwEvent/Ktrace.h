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

#include "Utils.h"

constexpr LPCWSTR ACTION_TTD = L"TTD";
constexpr LPCWSTR ACTION_DMP = L"DMP";
constexpr LPCWSTR TTD_REGISTRY_PATH = L".DEFAULT\\Software\\Microsoft\\TTT";
constexpr LPCWSTR TTD_PROCESS_NAME = L"TTTracer.exe";
constexpr LPCWSTR TTD_REGISTRY_EULA_KEY = L"EULASigned";
constexpr LPCWSTR TTD_DEFAULT_CMDLINE = L"-dumpFull -children -attach";
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

    /*
     * GetStopEvent()
     * Will return the Event that can be signeled to stop the trace
     */
    virtual HANDLE GetStopEvent() = 0;
};

//---------------------------------------------------------------------
// KernelTraceInstance()
// KernelTraceSession is a singleton.  Will return existing instance or
// create a new one before return.
//
// Returns NULL if setup failed, instance otherwise.
//---------------------------------------------------------------------
KernelTraceSession* KernelTraceInstance(LPWSTR, LPWSTR, LPWSTR, HANDLE);

//---------------------------------------------------------------------
// GetKernelTraceInstance()
// KernelTraceSession is a singleton and returns the existing instance.
// Returns NULL if setup failed, instance otherwise.
//---------------------------------------------------------------------
KernelTraceSession* GetKernelTraceInstance();

class KernelTraceSessionImpl : public KernelTraceSession
{
public:

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
        if (m_startTraceHandle)
        {
            HRESULT hr = ::ControlTrace(m_startTraceHandle, NT_LOGGER_SESSION_NAME, m_petp, EVENT_TRACE_CONTROL_STOP);

            if (hr != ERROR_SUCCESS)
            {
                Win32ErrorToString(L"ERROR: ControlTrace failed", HRESULT_FROM_WIN32(hr));
            }
        }

        if (m_stopEvent)
        {
            CloseHandle(m_stopEvent);
        }
    }

    //---------------------------------------------------------------------
    // Run()
    // Will block until SetStopFlag is called, so this should be called from a dedicated thread.
    //---------------------------------------------------------------------
    virtual void Run();

    virtual void Stop()
    {
        m_stopFlag = true;

        if (m_stopEvent != NULL)
        {
            SetEvent(m_stopEvent);
        }
    }

    //---------------------------------------------------------------------
    // Establish a session.
    // Returns true on success, false otherwise.
    //---------------------------------------------------------------------
    bool Setup();

    //---------------------------------------------------------------------
    // OnRecordEvent()
    // Called from StaticEventRecordCallback(), which is called by
    // ETW once ProcessEvent() is called.
    //---------------------------------------------------------------------
    void OnRecordEvent(PEVENT_RECORD);

    //---------------------------------------------------------------------
    // Called from StaticEventBufferCallback(), which is called by
    // ETW loop in ProcessSession().
    //
    // The only reason we implement this is to signal to ETW
    // to terminate this session's ProcessSession() loop.
    //---------------------------------------------------------------------
    bool OnBuffer(PEVENT_TRACE_LOGFILE);

    HRESULT DoActionDbg(HANDLE, DWORD, LPCWSTR);
    HRESULT DoActionTtd(DWORD);
    HANDLE GetStopEvent()
    {
        return m_stopEvent;
    }


private:

    //---------------------------------------------------------------------
    // Called from Setup() and will start the trace session
    //---------------------------------------------------------------------
    bool StartTraceSession(std::wstring, DWORD, TRACEHANDLE&);

    //---------------------------------------------------------------------
    // GetUserPropLen()
    // Calculates the length of user data properties that precede packet data.
    //---------------------------------------------------------------------
    DWORD GetUserPropLen(PEVENT_RECORD);

    //---------------------------------------------------------------------
    // OnRecordEventHandleImageLoad()
    // Specifically handles Image Load events
    //---------------------------------------------------------------------
    void OnRecordEventHandleImageLoad(PEVENT_RECORD, PTRACE_EVENT_INFO);

    bool m_stopFlag;
    TRACEHANDLE  m_startTraceHandle;
    int m_userPropLen;
    LPWSTR m_processName;
    LPWSTR m_moduleName;
    LPWSTR m_actionType;
    PEVENT_TRACE_PROPERTIES m_petp;
    HANDLE m_stopEvent;
};