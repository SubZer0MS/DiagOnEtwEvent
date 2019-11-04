#pragma once

#include <iostream>
#include <Windows.h>
#include <stdio.h>

constexpr LPCWSTR TTD_ACTION = L"TTD";
constexpr LPCWSTR DBG_ACTION = L"DBG";

// https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants

// https://docs.microsoft.com/en-us/windows/win32/etw/process

DEFINE_GUID( /* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */
    ProcessProviderGuid,
    0x3d6fa8d0,
    0xfe05,
    0x11d0,
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);

// https://docs.microsoft.com/en-us/windows/win32/etw/fileio
DEFINE_GUID( /* 90cbdc39-4a3e-11d1-84f4-0000f80464e3 */
    FileIoGuid,
    0x90cbdc39,
    0x4a3e,
    0x11d1,
    0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3
);