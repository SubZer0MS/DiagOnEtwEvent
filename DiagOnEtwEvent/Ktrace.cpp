#include "Ktrace.h"
#include "Utils.h"
#include "DiagOnEtwEvent.h"

KernelTraceSessionImpl* gKernelTraceSession = 0L;

//---------------------------------------------------------------------
// Run()
// Will block until SetStopFlag is called, so this should be called from a dedicated thread.
//---------------------------------------------------------------------
void KernelTraceSessionImpl::Run()
{
    m_stopFlag = false;

    // Process Trace - blocks until BufferCallback returns FALSE, or

    ULONG status = ProcessTrace(&m_startTraceHandle, 1, 0, 0);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
    {
        wprintf(L"KernelTraceSessionImpl: ProcessTrace() failed with %lu\n", status);
        CloseTrace(m_startTraceHandle);
    }
}

//---------------------------------------------------------------------
// OnRecordEvent()
// Called from StaticEventRecordCallback(), which is called by
// ETW once ProcessEvent() is called.
//---------------------------------------------------------------------
void KernelTraceSessionImpl::OnRecordEvent(PEVENT_RECORD pEvent)
{
    HRESULT hr = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[1];
    ULONG DescriptorsCount = 0;
    DWORD PropertySize = 0;
    PBYTE pData = NULL;
    HANDLE hProcess = NULL;
    LPWSTR commandLine = NULL;
    HANDLE hFile = NULL;

    //PrintEventMetadataWithProperties(pEvent);

    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
        pEvent->EventHeader.EventDescriptor.Opcode != EVENT_TRACE_TYPE_INFO &&
        m_stopFlag == false
        )
    {
        hr = GetEventInformation(pEvent, pInfo);
        if (ERROR_SUCCESS != hr)
        {
            wprintf(L"GetEventInformation failed with %lu\n", hr);
            goto cleanup;
        }
        
        if (pInfo->EventDescriptor.Opcode == EVENT_TRACE_TYPE_DC_START ||
            pInfo->EventDescriptor.Opcode == EVENT_TRACE_TYPE_LOAD)
        {
            if (wcscmp(L"ProcessId", ((LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[Image_Load::ProcessId].NameOffset))) == 0 &&
                wcscmp(L"FileName", ((LPWSTR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[Image_Load::FileName].NameOffset))) == 0
                )
            {
                hr = GetArraySize(pEvent, pInfo, 1, &ArraySize);
                if (ERROR_SUCCESS != hr)
                {
                    wprintf(L"GetArraySize failed with %lu\n", hr);
                    goto cleanup;
                }

                ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));
                DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[Image_Load::FileName].NameOffset);
                DataDescriptors[0].ArrayIndex = 0;
                DescriptorsCount = 1;

                hr = TdhGetPropertySize(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], &PropertySize);

                if (ERROR_SUCCESS != hr)
                {
                    wprintf(L"TdhGetPropertySize failed with %lu\n", hr);
                    goto cleanup;
                }

                pData = (PBYTE)malloc(PropertySize);

                if (NULL == pData)
                {
                    wprintf(L"Failed to allocate memory for property data\n");
                    hr = ERROR_OUTOFMEMORY;
                    goto cleanup;
                }

                hr = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);

                LPWSTR fileName = PathFindFileName((LPWSTR)pData);

                DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[Image_Load::ProcessId].NameOffset);

                hr = TdhGetPropertySize(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], &PropertySize);
                if (ERROR_SUCCESS != hr)
                {
                    wprintf(L"TdhGetPropertySize failed with %lu\n", hr);
                    goto cleanup;
                }

                PBYTE pDataTmp = (PBYTE)realloc(pData, PropertySize);
                if (NULL == pDataTmp)
                {
                    wprintf(L"Failed to allocate memory for property data\n");
                    hr = HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
                    goto cleanup;
                }
                else
                {
                    pData = pDataTmp;
                    pDataTmp = NULL;
                }

                if (NULL == pData)
                {
                    wprintf(L"Failed to allocate memory for property data\n");
                    hr = ERROR_OUTOFMEMORY;
                    goto cleanup;
                }

                hr = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);

                UINT32 processId = *(PULONG)pData;

                hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processId);
                if (hProcess == NULL)
                {
                    // we'll skip output of processes that already dissapered or system protected ones
                    hr = GetLastError();
                    if (hr != ERROR_INVALID_PARAMETER &&
                        hr != ERROR_ACCESS_DENIED
                        )
                    {
                        hr = HRESULT_FROM_WIN32(GetLastError());
                        wprintf(L"OpenProcess returned 0x%x for PID %d\n", hr, processId);
                    }

                    hr = ERROR_SUCCESS;
                    goto cleanup;
                }

                WCHAR filePath[MAX_PATH + 1];
                hr = GetModuleFileNameEx(hProcess, NULL, filePath, MAX_PATH + 1);

                LPCWSTR processName = NULL;
                if (hr != NULL)
                {
                    processName = PathFindFileName(filePath);
                    if (hr == NULL)
                    {
                        hr = HRESULT_FROM_WIN32(GetLastError());
                        wprintf(L"PathFindFileName failed: 0x%x\n", hr);
                        goto cleanup;
                    }
                }

                //wprintf(L"Process is: %s and module is: %s", processName, fileName);

                if (processName != NULL && fileName != NULL)
                {
                    LPWSTR fileExtension = PathFindExtension(fileName);

                    if (_wcsicmp(fileExtension, L".dll") == 0 &&
                        _wcsicmp(processName, m_processName) == 0
                        )
                    {
                        std::wstring rawName(fileName);
                        rawName = rawName.substr(0, rawName.find_last_of(L"."));

                        // we need to verify if this will load a pre-compiled (ni - native compiled) managed DLL
                        if (_wcsicmp(PathFindExtension(rawName.c_str()), L".ni") == 0)
                        {
                            rawName = rawName.substr(0, rawName.find_last_of(L"."));
                        }

                        std::wstring rawModule(m_moduleName);

                        if (_wcsicmp(rawName.c_str(), rawModule.substr(0, rawModule.find_last_of(L".")).c_str()) == 0)
                        {
                            wprintf(L"Found process %s and module %s and performing action %s\n", processName, fileName, m_actionType);

                            if (_wcsicmp(ACTION_DMP, m_actionType) == 0)
                            {
                                wprintf(L"Writing full memory user dump ...\n");

                                const DWORD Flags = 
                                    MiniDumpWithFullMemory |
                                    MiniDumpWithFullMemoryInfo |
                                    MiniDumpWithHandleData |
                                    MiniDumpWithUnloadedModules |
                                    MiniDumpWithThreadInfo;

                                WCHAR dumpFileTime[MAX_PATH];
                                dumpFileTime[0] = '\0';
                                struct tm timenow;
                                __int64 ltime;
                                _time64(&ltime);
                                errno_t err = gmtime_s(&timenow, &ltime);
                                if (err)
                                {
                                    hr = HRESULT_FROM_WIN32(err);
                                    wprintf(L"ERROR: Failed to create date time for file name with error 0x%x\n", hr);
                                    goto cleanup;
                                }

                                wcsftime(dumpFileTime, MAX_PATH, L"%Y_%m_%d_%H_%M_%S", &timenow);
                                WCHAR dumpFileName[MAX_PATH];
                                StringCbPrintf(dumpFileName, MAX_PATH, L"%s_%s.dmp", processName, dumpFileTime);
                                
                                hFile = CreateFile(dumpFileName, GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                                if (hFile == NULL)
                                {
                                    hr = GetLastError();
                                    wprintf(L"ERROR: Failed to create the file for the memory dump with error 0x%x\n", HRESULT_FROM_WIN32(hr));
                                    goto cleanup;
                                }

                                if (!MiniDumpWriteDump(
                                    hProcess,
                                    processId,
                                    hFile,
                                    (MINIDUMP_TYPE)Flags,
                                    nullptr,
                                    nullptr,
                                    nullptr)
                                    )
                                {
                                    hr = GetLastError();
                                    wprintf(L"ERROR: Failed to write the memory dump with error 0x%x\n", HRESULT_FROM_WIN32(hr));
                                    goto cleanup;
                                }

                                wprintf(L"Memory dump file was successfully written to: %s\n", dumpFileName);

                                Stop();
                            }
                            else if (_wcsicmp(ACTION_TTD, m_actionType) == 0)
                            {
                                STARTUPINFO si;
                                PROCESS_INFORMATION pi;
                                ZeroMemory(&si, sizeof(si));
                                si.cb = sizeof(si);
                                ZeroMemory(&pi, sizeof(pi));

                                commandLine = (LPWSTR)malloc(sizeof(WCHAR) * MAX_PATH);
                                commandLine[0] = '\0';
                                wcscat_s(commandLine, MAX_PATH, TTD_DEFAULT_CMDLINE);

                                WCHAR processIdString[10];
                                _ultow_s(processId, processIdString, 10, 10);
                                wcscat_s(commandLine, MAX_PATH, processIdString);

                                LPDWORD result = 0;
                                HKEY registryKey = NULL;
                                hr = RegCreateKeyEx(HKEY_USERS, TTD_REGISTRY_PATH, 0, NULL, NULL, KEY_ALL_ACCESS, NULL, &registryKey, result);
                                if (hr != ERROR_SUCCESS)
                                {
                                    wprintf(L"ERROR: Failed to create/open the TTD EULA registry key with error 0x%x\n", HRESULT_FROM_WIN32(hr));
                                    goto cleanup;
                                }

                                DWORD value = 1;
                                hr = RegSetValueEx(registryKey, TTD_REGISTRY_EULA_KEY, 0, REG_DWORD, (const BYTE*)&value, sizeof(value));

                                RegCloseKey(registryKey);

                                if (hr != ERROR_SUCCESS)
                                {
                                    wprintf(L"ERROR: Failed to set EULASigned registry value for TTD EULA registry key with error 0x%x\n", HRESULT_FROM_WIN32(hr));
                                    goto cleanup;
                                }

                                wprintf(L"Attaching TTD ... with command line: %s\n", commandLine);

                                if (!CreateProcess(
                                    TTD_PROCESS_NAME,    // Process name
                                    commandLine,    // Command line
                                    NULL,    // Process handle not inheritable
                                    NULL,    // Thread handle not inheritable
                                    FALSE,   // Set handle inheritance to FALSE
                                    0,       // No creation flags
                                    NULL,    // Use parent's environment block
                                    NULL,    // Use parent's starting directory 
                                    &si,     // Pointer to STARTUPINFO structure
                                    &pi      // Pointer to PROCESS_INFORMATION structure
                                ))
                                {
                                    hr = GetLastError();

                                    if (hr == ERROR_FILE_NOT_FOUND)
                                    {
                                        wprintf(L"ERROR: This program (executable) needs to be in the same folder as TTTRacer.exe and its dependent files.\n");
                                    }
                                    else
                                    {
                                        wprintf(L"ERROR: Could not start the process with error 0x%x\n", HRESULT_FROM_WIN32(hr));
                                    }

                                    goto cleanup;
                                }

                                // Wait until child process exits.
                                WaitForSingleObject(pi.hProcess, INFINITE);

                                // Close process and thread handles. 
                                CloseHandle(pi.hProcess);
                                CloseHandle(pi.hThread);

                                Stop();
                            }
                        }
                    }
                }
            }
        }
    }

cleanup:

    if (pInfo)
    {
        free(pInfo);
    }

    if (pData)
    {
        free(pData);
        pData = NULL;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = NULL;
    }

    if (commandLine)
    {
        free(commandLine);
    }

    if (hProcess)
    {
        CloseHandle(hProcess);
    }

    if (hFile)
    {
        CloseHandle(hFile);
    }
}

//---------------------------------------------------------------------
// Called from StaticEventBufferCallback(), which is called by
// ETW loop in ProcessSession().
//
// The only reason we implement this is to signal to ETW
// to terminate this session's ProcessSession() loop.
//---------------------------------------------------------------------
BOOL KernelTraceSessionImpl::OnBuffer(PEVENT_TRACE_LOGFILE buf)
{
    if (m_stopFlag)
    {
        return FALSE; // I'm done. Stop sending and exit ProcessSession()
    }

    return TRUE; // keep sending me events!
}


//---------------------------------------------------------------------
// Called from Setup()
//---------------------------------------------------------------------
bool KernelTraceSessionImpl::StartTraceSession(std::wstring mySessionName, DWORD dwEnableFlags, TRACEHANDLE& traceSessionHandle)
{
    std::vector<unsigned char>	vecEventTraceProps;	//EVENT_TRACE_PROPERTIES || name

    vecEventTraceProps.resize(sizeof(EVENT_TRACE_PROPERTIES) + (mySessionName.length() + 1) * sizeof(mySessionName[0]));
    m_petp = (PEVENT_TRACE_PROPERTIES)&vecEventTraceProps[0];
    m_petp->Wnode.BufferSize = (ULONG)vecEventTraceProps.size();
    m_petp->Wnode.Guid = SystemTraceControlGuid;	// For kernel trace, have to use this shared GUID
    m_petp->Wnode.ClientContext = 1;	//use QPC for timestamp resolution
    m_petp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    m_petp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    m_petp->FlushTimer = 1;
    m_petp->LogFileNameOffset = 0;
    m_petp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    m_petp->EnableFlags = dwEnableFlags;

    // Call StartTrace() to setup a realtime ETW context associated with Guid + mySessionName
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364117(v=vs.85).aspx

    ULONG hr = ::StartTrace(&traceSessionHandle, mySessionName.c_str(), m_petp);
    if (ERROR_ALREADY_EXISTS == hr)
    {
        hr = ::ControlTrace(traceSessionHandle, mySessionName.c_str(), m_petp, EVENT_TRACE_CONTROL_UPDATE);

        if (hr != ERROR_SUCCESS)
        {
            printf("ControlTrace returned %ul\n", hr);
            traceSessionHandle = 0L;
            return false;
        }
    }
    else if (hr != ERROR_SUCCESS)
    {
        printf("StartTraceW returned %ul\n", hr);
        traceSessionHandle = 0L;
        return false;
    }
    else
    {
        hr = EnableTraceEx2(traceSessionHandle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
        if (hr != ERROR_SUCCESS)
        {
            printf("EnableTraceEx2 returned %ul\n", hr);
            traceSessionHandle = 0L;
            return false;
        }
    }
    
    return true;
}

//---------------------------------------------------------------------
// Function wrapper to call our class OnRecordEvent()
//---------------------------------------------------------------------
static VOID WINAPI StaticRecordEventCallback(PEVENT_RECORD pEvent)
{
    if (0L == gKernelTraceSession) return;
    gKernelTraceSession->OnRecordEvent(pEvent);
}

//---------------------------------------------------------------------
// Function wrapper to call our class OnBuffer()
//---------------------------------------------------------------------
static BOOL WINAPI StaticBufferEventCallback(PEVENT_TRACE_LOGFILE buf)
{
    if (0L == gKernelTraceSession) return FALSE;
    return gKernelTraceSession->OnBuffer(buf);
}

//---------------------------------------------------------------------
// Establish a session.
// Returns true on success, false otherwise.
//---------------------------------------------------------------------
bool KernelTraceSessionImpl::Setup()
{
    // This is where you wask for Process information, TCP, etc.  Look at StartTraceW() docs.

    DWORD kernelTraceOptions = EVENT_TRACE_FLAG_IMAGE_LOAD; // EVENT_TRACE_FLAG_DISK_FILE_IO; // EVENT_TRACE_FLAG_PROCESS

    ULONG status = StartTraceSession(NT_LOGGER_SESSION_NAME, kernelTraceOptions, this->m_startTraceHandle);

    if (status == false)
        return false;

    // Identify the log file from which you want to consume events
    // and the callbacks used to process the events and buffers.

    EVENT_TRACE_LOGFILE trace;
    TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
    ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
    trace.LoggerName = (LPWSTR)NT_LOGGER_SESSION_NAME;
    trace.LogFileName = (LPWSTR)NULL;

    // hook up our callback functions

    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(StaticRecordEventCallback);
    trace.BufferCallback = (PEVENT_TRACE_BUFFER_CALLBACK)(StaticBufferEventCallback);
    trace.Context = this; // passes to EventRecordCallback, but only works in Vista+

    trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

    // Open Trace

    this->m_startTraceHandle = OpenTrace(&trace);
    if (INVALID_PROCESSTRACE_HANDLE == this->m_startTraceHandle)
    {
        DWORD err = GetLastError();
        wprintf(L"KernelTraceSession: OpenTrace() failed with %lu\n", err);	// lookup in winerror.h
        goto cleanup;
    }

    return true;

cleanup:
    CloseTrace(this->m_startTraceHandle);
    return false;
}

//---------------------------------------------------------------------
// GetUserPropLen()
// Calculates the length of user data properties that precede packet data.
//---------------------------------------------------------------------
DWORD KernelTraceSessionImpl::GetUserPropLen(PEVENT_RECORD pEvent)
{
    PTRACE_EVENT_INFO pInfo = 0L;
    DWORD BufferSize = 0;

    // Retrieve the required buffer size for the event metadata.

    DWORD status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
        if (pInfo == NULL)
        {
            wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
            return ERROR_OUTOFMEMORY;
        }

        // Retrieve the event metadata.

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
    }

    if (ERROR_SUCCESS != status) return status;

    // loop through properties

    int proplen = 0;
    for (uint32_t i = 0; i < pInfo->PropertyCount; i++)
    {
        if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
            continue; // buffer, defined by previous property length
        proplen += pInfo->EventPropertyInfoArray[i].length;
    }

    // proplen now contains offset to start of packet bytes inside UserData

    if (proplen > 0) m_userPropLen = proplen;

    free(pInfo);
    return status;
}

//---------------------------------------------------------------------
// KernelTraceInstance()
// KernelTraceSession is a singleton.  Will return existing instance or
// create a new one before return.
//
// Returns NULL if setup failed, instance otherwise.
//---------------------------------------------------------------------
KernelTraceSession* KernelTraceInstance(LPWSTR processName, LPWSTR moduleName, LPWSTR actionType) {

    if (gKernelTraceSession != 0L) return gKernelTraceSession;

    KernelTraceSessionImpl* obj = new KernelTraceSessionImpl(processName, moduleName, actionType);

    if (obj->Setup() == false) {
        printf("KernelTraceSession Setup failed\n");
        delete obj;
        return 0L;
    }

    gKernelTraceSession = obj;

    return obj;
}
