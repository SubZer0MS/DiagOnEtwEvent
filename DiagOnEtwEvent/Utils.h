#pragma once

#include <comdef.h>
#include <guiddef.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <tdh.h>
#include <in6addr.h>

#pragma comment(lib, "ws2_32.lib")

constexpr int MAX_NAME = 256;

typedef LPTSTR(NTAPI* PIPV6ADDRTOSTRING)(const PIN6_ADDR, LPTSTR);

static PCWCHAR g_pSource[] = { L"XML instrumentation manifest", L"WMI MOF class", L"WPP TMF file" };

void PrintCSBackupAPIErrorMessage(DWORD);
DWORD PrintProperties(PEVENT_RECORD, PTRACE_EVENT_INFO, USHORT, LPWSTR, USHORT);
DWORD GetEventInformation(PEVENT_RECORD, PTRACE_EVENT_INFO&);
DWORD PrintPropertyMetadata(TRACE_EVENT_INFO*, DWORD, USHORT);
void PrintEventMeta(PEVENT_RECORD);
DWORD FormatAndPrintData(PEVENT_RECORD, USHORT, USHORT, PBYTE, DWORD, PEVENT_MAP_INFO);
void PrintMapString(PEVENT_MAP_INFO, PBYTE);
DWORD GetArraySize(PEVENT_RECORD, PTRACE_EVENT_INFO, USHORT, PUSHORT);
DWORD GetMapInfo(PEVENT_RECORD, LPWSTR, DWORD, PEVENT_MAP_INFO&);
void RemoveTrailingSpace(PEVENT_MAP_INFO);
void PrintEventMetadataWithProperties(PEVENT_RECORD);