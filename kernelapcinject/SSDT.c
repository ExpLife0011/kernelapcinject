#include <Ntifs.h>
#include <ntddk.h>
#include "ctl.h"

//老外定位KeServiceDescriptorTable的方法  

PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;
ULONGLONG GetKeServiceDescriptorTable64()
{
	char KiSystemServiceStart_pattern[] = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00";   //特征码  
	ULONGLONG CodeScanStart = (ULONGLONG)&_strnicmp;
	ULONGLONG CodeScanEnd = (ULONGLONG)&KdDebuggerNotPresent;
	UNICODE_STRING Symbol;
	ULONGLONG i, tbl_address, b;
	for (i = 0; i < CodeScanEnd - CodeScanStart; i++)
	{
		if (!memcmp((char*)(ULONGLONG)CodeScanStart + i, (char*)KiSystemServiceStart_pattern, 13))
		{
			for (b = 0; b < 50; b++)
			{
				tbl_address = ((ULONGLONG)CodeScanStart + i + b);
				if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
					return ((LONGLONG)tbl_address + 7) + *(LONG*)(tbl_address + 3);
			}
		}
	}
	return 0;
}

//根据KeServiceDescriptorTable找到SSDT基址  
PULONG GetSSDTBaseAddress()
{
	PULONG addr = NULL;
	PSYSTEM_SERVICE_TABLE ssdt = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable64();
	addr = (PULONG)(ssdt->ServiceTableBase);
	return addr;
}
ULONGLONG GetSSDTBaseAddr()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i<EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *(i);
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
			{
				memcpy(&templong, i + 3, 4);
				//核心部分
				//kd> db fffff800`03e8b772
				//fffff800`03e8b772  4c 8d 15 c7 20 23 00 4c-8d 1d 00 21 23 00 f7 83  L... #.L...!#...
				//templong = 002320c7 ,i = 03e8b772, 7为指令长度
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	DbgPrint("b1 = %0x\n", b1);
	DbgPrint("b2 = %0x\n", b2);
	DbgPrint("b3 = %0x", b3);
	DbgPrint("templong = %0x\n", templong);
	DbgPrint("addr = %0x\n", addr);
	return addr;
}
//根据标号找到SSDT表中函数的地址  
ULONGLONG GetFuncAddr(ULONG id)
{
	LONG dwtmp = 0;
	ULONGLONG addr = 0;
	PULONG stb = NULL;
	KeServiceDescriptorTable = GetSSDTBaseAddr();
	stb = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = stb[id];
	dwtmp = dwtmp >> 4;
	addr = (LONGLONG)dwtmp + (ULONGLONG)stb;
	DbgPrint("SSDT TABLE BASEADDRESS:%llx", addr);
	return addr;
}
SIZE_T GetNtosFunctionAddress(PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString(&UniCodeFunctionName, FunctionName);
	return (SIZE_T)MmGetSystemRoutineAddress(&UniCodeFunctionName);
}

SIZE_T GetZwFuncAddress(ULONG id)
{
	SIZE_T f0Addr = 0, RetAddr = 0, pZwClose = GetNtosFunctionAddress(L"ZwClose");
	ULONG ZwFunLen = 0, ZwCloseIndex = 0;
#ifdef AMD64
	ZwFunLen = 32;
	memcpy(&ZwCloseIndex, (PUCHAR)pZwClose + 21, 4);
#else
	ZwFunLen = 20;
	memcpy(&ZwCloseIndex, (PUCHAR)pZwClose + 1, 4);
#endif
	f0Addr = pZwClose - ZwCloseIndex*ZwFunLen;
	RetAddr = f0Addr + id*ZwFunLen;
	DbgPrint("%p\n", RetAddr);
	return RetAddr;
}