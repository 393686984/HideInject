#pragma once
#include <ntifs.h>

NTSTATUS InjectX64(HANDLE pid, char *shellcode, SIZE_T shellcodeSize);

NTSTATUS InjectX86(HANDLE pid, char *shellcode, SIZE_T shellcodeSize);