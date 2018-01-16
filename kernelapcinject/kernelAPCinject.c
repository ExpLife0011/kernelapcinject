#include <Ntifs.h>
#include <ntddk.h>
#include "ctl.h"

#define Read CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF30, METHOD_NEITHER, FILE_ANY_ACCESS)
#define Write CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF31, METHOD_NEITHER, FILE_ANY_ACCESS)
#define ReadTEXT CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF32, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MDL_shellcode CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF33, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MDL_shellcode2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF34, METHOD_NEITHER, FILE_ANY_ACCESS)
#define MALLOC_NPP(_s)        ExAllocatePool(NonPagedPool, _s)
#define FREE(_p)        ExFreePool(_p)
#define DEVICE_NAME L"\\Device\\InsertApcDrv" 
#define LINK_NAME L"\\??\\My_DriverLinkName" 
#define AMD64_SOURCES = test.asm
NTKERNELAPI
VOID
KeInitializeApc(
__out PRKAPC Apc,
__in PRKTHREAD Thread,
__in KAPC_ENVIRONMENT Environment,
__in PKKERNEL_ROUTINE KernelRoutine,
__in_opt PKRUNDOWN_ROUTINE RundownRoutine,
__in_opt PKNORMAL_ROUTINE NormalRoutine,
__in_opt KPROCESSOR_MODE ProcessorMode,
__in_opt PVOID NormalContext
);
NTSYSAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
IN PRKAPC Apc,
IN PVOID SystemArgument1 OPTIONAL,
IN PVOID SystemArgument2 OPTIONAL,
IN KPRIORITY Increment
);
KIRQL
KeGetCurrentIrql(
VOID
);

/*typedef ULONG64(__stdcall *SCFN)(ULONG64);
ULONG64 test(ULONG64 VMDL)
{
	SCFN scfn;
	UINT64 ret;
	const UCHAR strShellCode[14] = { 0x67, 0x48, 0x8B, 0x45, 0x08, 0x48, 0xF7, 0xD8, 0x48, 0xC1, 0xE0, 0x02, 0xC3 };
	
	scfn = ExAllocatePool(NonPagedPool, 14);
	memcpy(scfn, strShellCode, 14);
	ret = scfn(VMDL);
	DbgPrint("[x64Drv] Inline ASM return: %lld", ret);
	ExFreePool(scfn);
	return ret;
}*/


ULONGLONG pMappedAddress =NULL;
NTKERNELAPI NTSTATUS NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
int PTESize;
UINT_PTR PAGE_SIZE_LARGE;
UINT_PTR MAX_PDE_POS;
UINT_PTR MAX_PTE_POS;
PMDL pMdl = NULL;
//这个是针对某个静态程序的测试
const UCHAR shellcode32[] = {
	/*自行脑补一个*/
	0x60,0x6a,0x44,0xA1,0x00,0x60,0x41,0x00,
	0x50,0x8B,0x0d,0x00,0x60,0x41,0x00,0x51,
	0x6a,0x00,0xff,0x15,0x0C,0x71,0x41,0x00,
	0x61,0xc3

};
struct PTEStruct
{
	unsigned P : 1; // present (1 = present)
	unsigned RW : 1; // read/write
	unsigned US : 1; // user/supervisor
	unsigned PWT : 1; // page-level write-through
	unsigned PCD : 1; // page-level cache disabled
	unsigned A : 1; // accessed
	unsigned Reserved : 1; // dirty
	unsigned PS : 1; // page size (0 = 4-KB page)
	unsigned G : 1; // global page
	unsigned A1 : 1; // available 1 aka copy-on-write
	unsigned A2 : 1; // available 2 is 1 when paged to disk
	unsigned A3 : 1; // available 3
	unsigned PFN : 20; // page-frame number
};
void InitMemSafe()
{
#ifndef AMD64
	ULONG cr4reg;
	//determine if PAE is used
	cr4reg = (ULONG)__readcr4();
	if ((cr4reg & 0x20) == 0x20)
	{
		PTESize = 8; //pae
		PAGE_SIZE_LARGE = 0x200000;
		MAX_PDE_POS = 0xC0604000;
		MAX_PTE_POS = 0xC07FFFF8;
	}
	else
	{
		PTESize = 4;
		PAGE_SIZE_LARGE = 0x400000;
		MAX_PDE_POS = 0xC0301000;
		MAX_PTE_POS = 0xC03FFFFC;
	}
#else
	PTESize = 8; //pae
	PAGE_SIZE_LARGE = 0x200000;
	MAX_PTE_POS = 0xFFFFF6FFFFFFFFF8ULL;
	MAX_PDE_POS = 0xFFFFF6FB7FFFFFF8ULL;
#endif
}
VOID  KrnlApcSetAlertable(
	PKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
	)
{
	LARGE_INTEGER Timeout;

	ARGUMENT_PRESENT(NormalRoutine);
	ARGUMENT_PRESENT(NormalContext);
	ARGUMENT_PRESENT(SystemArgument1);
	ARGUMENT_PRESENT(SystemArgument2);

	Timeout.QuadPart = 0;
	KeDelayExecutionThread(UserMode, TRUE, &Timeout);

	if (NULL != Apc)
	{
		ExFreePool((PVOID)Apc);
	}

}


BOOLEAN IsAddressSafe(UINT_PTR StartAddress)
{
#ifdef AMD64
	//cannonical check. Bits 48 to 63 must match bit 47
	UINT_PTR toppart = (StartAddress >> 47);
	if (toppart & 1)
	{
		//toppart must be 0x1ffff
		if (toppart != 0x1ffff)
			return FALSE;
	}
	else
	{
		//toppart must be 0
		if (toppart != 0)
			return FALSE;

	}
#endif
	//PDT+PTE judge
	{
#ifdef AMD64
		UINT_PTR kernelbase = 0x7fffffffffffffffULL;
		if (StartAddress<kernelbase)
		{
			return TRUE;
		}
		else
		{
			PHYSICAL_ADDRESS physical;
			physical.QuadPart = 0;
			physical = MmGetPhysicalAddress((PVOID)StartAddress);
			return (physical.QuadPart != 0);
		}
		return TRUE; //for now untill I ave figure out the win 4 paging scheme
#else
		ULONG kernelbase = 0x7ffe0000;
		UINT_PTR PTE, PDE;
		struct PTEStruct *x;
		if (StartAddress<kernelbase)
		{
			return TRUE;
		}
		PTE = (UINT_PTR)StartAddress;
		PTE = PTE / 0x1000 * PTESize + 0xc0000000;
		//now check if the address in PTE is valid by checking the page table directory at 0xc0300000 (same location as CR3 btw)
		PDE = PTE / 0x1000 * PTESize + 0xc0000000; //same formula
		x = (struct PTEStruct *)PDE;
		if ((x->P == 0) && (x->A2 == 0))
		{
			//Not present or paged, and since paging in this area isn't such a smart thing to do just skip it
			//perhaps this is only for the 4 mb pages, but those should never be paged out, so it should be 1
			//bah, I've got no idea what this is used for
			return FALSE;
		}
		if (x->PS == 1)
		{
			//This is a 4 MB page (no pte list)
			//so, (startaddress/0x400000*0x400000) till ((startaddress/0x400000*0x400000)+(0x400000-1) ) ) is specified by this page
		}
		else //if it's not a 4 MB page then check the PTE
		{
			//still here so the page table directory agreed that it is a usable page table entry
			x = (PVOID)PTE;
			if ((x->P == 0) && (x->A2 == 0))
				return FALSE; //see for explenation the part of the PDE
		}
		return TRUE;
#endif
	}
}
PETHREAD LookupThread(HANDLE handle)
{
	NTSTATUS status;
	PETHREAD PThread;
	status = PsLookupThreadByThreadId(handle, &PThread);
	if (status == STATUS_SUCCESS)
	{
		return PThread;
	}
	else
	{
		return NULL;
	}
}
VOID ReadWriteProcessMemoryApc(PKAPC pApc,PKNORMAL_ROUTINE *NormalRoutine,PVOID *NormalContext,PVOID *SystemArgument1,PVOID *SystemArgument2)
{
        PRWPM_INFO pInfo = (PRWPM_INFO)(pApc->NormalContext);
		InitMemSafe();
        if(pInfo->Type==0)
        {
			if (IsAddressSafe(pInfo->Address))
			{
				DbgPrint("访问的地址安全！\n");
				if (pInfo->Address > 0x7fffffff)
				{
					_try
					{
						_disable();
						__writecr0(__readcr0() & 0xfffffffffffeffff);//64位写CR0寄存器WP位为0    
						RtlCopyMemory(pInfo->Buffer, pInfo->Address, pInfo->Length);//read
						__writecr0(__readcr0() | 0x10000);  //64位写CR0寄存器WP位为1           
						_enable();
					}
						_except(1)
					{
						;
					}
				}
				else
				{
					_try
					{
						RtlCopyMemory(pInfo->Buffer, pInfo->Address, pInfo->Length);//read
					}
						_except(1)
					{
						;
					}
				}
			}
			else
			{
				DbgPrint("读取的地址无效！\n");
			}
		
        }
        else
        {
                _try
                {
                        _disable();        
                        __writecr0(__readcr0() & 0xfffffffffffeffff);//64位写CR0寄存器WP位为0    
                        RtlCopyMemory(pInfo->Address,pInfo->Buffer,pInfo->Length);//write
                        __writecr0(__readcr0() | 0x10000);  //64位写CR0寄存器WP位为1           
                        _enable();        
                }
                _except(1)
                {
                        ;
                }
        }
        pInfo->Type=2;
        KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
        ExFreePool(pApc);
}
NTSTATUS InsertReadWriteProcessMemoryApc(PETHREAD Thread, PRWPM_INFO pInfo)
{
        NTSTATUS st = STATUS_UNSUCCESSFUL;
        PKAPC pApc = 0;
		//pApc = (PKAPC)((ULONG)Thread + EtOffset);


		if (MmIsAddressValid(Thread))
        {
                pApc = MALLOC_NPP( sizeof(KAPC)); 
                if (pApc)
                {
                        LARGE_INTEGER interval={0};
                        KeInitializeApc(pApc, Thread, OriginalApcEnvironment, ReadWriteProcessMemoryApc, 0, 0, KernelMode, 0);
                        pApc->NormalContext = pInfo;
                        KeInitializeEvent(&(pInfo->Event),NotificationEvent,TRUE);
                        KeClearEvent(&(pInfo->Event));
                        if(KeInsertQueueApc(pApc, 0, 0, 0))
                        {
                                interval.QuadPart = -10000;//DELAY_ONE_MILLISECOND;
                                interval.QuadPart *= 1000;
                                st = KeWaitForSingleObject(&(pInfo->Event),Executive,KernelMode,0,&interval);
                        }
                        else
                        {
							FREE(pApc);
                        }
						
                }
        }
        return st;
}


BOOLEAN ForceReadProcessMemory2(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, OUT PVOID Buffer)
{
        ULONG i;
        BOOLEAN b = 0;
        for(i=8; i<1000000; i=i+4)
        {
                PETHREAD ethrd=LookupThread((HANDLE)i);

                if(ethrd!=NULL)
                {

                        PEPROCESS eproc=IoThreadToProcess(ethrd);
                        ObDereferenceObject(ethrd);
                        if(eproc==Process)
                        {
                                PRWPM_INFO pInfo = MALLOC_NPP(sizeof(RWPM_INFO));
                                pInfo->Address = Address;
                                pInfo->Buffer = Buffer;
                                pInfo->Length = Length;
                                pInfo->Type = 0;
                                if(NT_SUCCESS(InsertReadWriteProcessMemoryApc(ethrd, pInfo)))
                                {
                                        FREE(pInfo);
                                        b=1;break;
                                }
                        }
                }
        }
        return b;
}

BOOLEAN ForceWriteProcessMemory2(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, IN PVOID Buffer)
{
        ULONG i;
        BOOLEAN b = 0;
        for(i=8; i<1000000; i=i+4)
        {
                PETHREAD ethrd = LookupThread((HANDLE)i);
                if(ethrd!=NULL)
                {
                        PEPROCESS eproc=IoThreadToProcess(ethrd);
                        ObDereferenceObject(ethrd);
                        if(eproc==Process)
                        {
                                PRWPM_INFO pInfo = MALLOC_NPP(sizeof(RWPM_INFO));
                                pInfo->Address = Address;
                                pInfo->Buffer = Buffer;
                                pInfo->Length = Length;
                                pInfo->Type = 1;
                                if(NT_SUCCESS(InsertReadWriteProcessMemoryApc(ethrd, pInfo)))
                                {
                                        FREE(pInfo);
                                        b=1;break;
                                }
                        }
                }
        }
        return b;
}
VOID  UserApcFreeApc(
	PKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2)
{
	ARGUMENT_PRESENT(NormalRoutine);
	ARGUMENT_PRESENT(NormalContext);
	ARGUMENT_PRESENT(SystemArgument1);
	ARGUMENT_PRESENT(SystemArgument2);


	if (NULL != Apc)
	{
		ExFreePool(Apc);
	}

}
NTSTATUS APC_MDL_Shellcode_2(PETHREAD thread, PVOID pMappedAddress, PEPROCESS Process){
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER interval = { 0 };
	ULONG INt = NULL;
	PVOID THFR = NULL;
	ULONG ApcStateOffset;
	PKAPC_STATE ApcState = NULL;
	PKAPC UserApc = MALLOC_NPP(sizeof(KAPC));
	PRKAPC pApc = MALLOC_NPP(sizeof(KAPC));
	
	if (NULL != UserApc && NULL != pApc)
	{
		KeInitializeApc(UserApc, thread, OriginalApcEnvironment, UserApcFreeApc, NULL, ((LONG_PTR)pMappedAddress * (-4)), UserMode, 0);

		//WOW64需要处理下，(PKNORMAL_ROUTINE)((0 - (ULONG_PTR)pMappedAddress) << 2)
		/*PULONG ptr = (PULONG)thread;
		for ( INT i = 0; i<512; i++)
		{
		if (ptr[i] == (ULONG)Process)
		{
		ApcState = CONTAINING_RECORD(&ptr[i], KAPC_STATE, Process);
		ApcStateOffset = (ULONG)ApcState - (ULONG)thread;
		break;
		}
		}
		ApcState->UserApcPending = TRUE;
		DbgPrint("ApcState offset: %#x\n", ApcStateOffset);*/

		if (!KeInsertQueueApc(UserApc, 0, 0, 0))
		{
			DbgPrint("lzplhq -> Failed to insert APC");
			//MmUnlockPages(pMdl);
			//IoFreeMdl(pMdl);
			ExFreePool(UserApc);
			ExFreePool(pApc);
		}
		else
		{
			KeInitializeApc(pApc, thread, OriginalApcEnvironment, KrnlApcSetAlertable, NULL, NULL, KernelMode, NULL);
			st = KeInsertQueueApc(pApc, NULL, NULL, IO_NO_INCREMENT);
			if (!st)
			{
				ExFreePool(pApc);
			}
		}

	}
	else
	{

		if (NULL != UserApc)
		{
			ExFreePool(UserApc);
		}

		if (NULL != pApc)
		{
			ExFreePool(pApc);
		}

	}
	return st;
}
VOID FillApc(IN struct _KAPC *Apc,
	IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2){
	PMDLSHECODE pInfo = (PMDLSHECODE)(Apc->NormalContext);
	ULONG pBaseAddr = NULL;
	/*st = ObOpenObjectByPointer(
		Process,
		0,
		NULL,
		NULL,
		NULL,
		KernelMode,
		&Processhandle
		);
	if (st != STATUS_SUCCESS)
	{
		DbgPrint("获取句柄失败！\n");
	}*/
	//ZwAllocateVirtualMemory(pInfo->eproshandle, (PVOID*)&pBaseAddr, 0, 41, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	
	pMappedAddress = MmMapLockedPagesSpecifyCache(pInfo->mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
	if (pMappedAddress == NULL)

	{
		DbgPrint("虚拟地址映射失败");
		IoFreeMdl(pMdl);
	}
	else
	{
		DbgPrint("%x", pMappedAddress);

	}
	
	KeSetEvent(&(pInfo->Event), IO_NO_INCREMENT, FALSE);
	

}


NTSTATUS APC_MDL_Shellcode_1( PEPROCESS Process,shellcode_MDL buffer)
{
	//PRKAPC pApc = NULL;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	KAPC_STATE ApcState;
	ULONG i;
	BOOLEAN b = 0;
	//pApc = MALLOC_NPP(sizeof(KAPC));
	//pMdl =  MALLOC_NPP(sizeof(MDL));
	MDZZ mdzz;
	HANDLE ethrdhandle = NULL, Processhandle = NULL;
	KAPC_STATE		ApcStAte;
	ULONGLONG pBaseAddr = NULL;
	SIZE_T LENGTH = sizeof(shellcode32);
	__try{

	//这里使用正常的申请内存，不用自己实现插apc，挂靠进程状态域ApcStAte(KeStackAttachProcess就是靠挂ApcStAte，其实插apc也可以完成的)。
	
	//ASSERT(pMdl != NULL);

		for (i = 8; i < 1048576; i = i + 4)
	{
		PETHREAD ethrd = LookupThread((HANDLE)i);
		if (ethrd != NULL)
		{
			PEPROCESS eproc = IoThreadToProcess(ethrd);
			ObDereferenceObject(ethrd);
			if (eproc == Process)
			{
				//ULONGLONG I = (ULONGLONG)ethrd+0x4c;
				//if (((pmdzz)I)->Alertable)
				//{
					//DbgPrint("是可警醒的线程\n");
					KeStackAttachProcess((PEPROCESS)Process, &ApcStAte);

					//KeAttachProcess(Process);
					PULONG ptr = (PULONG)ethrd;
					LARGE_INTEGER interval = { 0 };
					//PMDLSHECODE pInfo = MALLOC_NPP(sizeof(MDLSHECODE));
					//pInfo->eproshandle = ethrdhandle;

					//pInfo->epros = Process;
					//pMdl = IoAllocateMdl(buffer, 58, FALSE, FALSE, NULL);
					//pInfo->ethrd = ethrd;
					//pInfo->mdl = pMdl;
					//KeInitializeApc(pApc, ethrd, OriginalApcEnvironment, FillApc, 0, 0, KernelMode, 0);
					//pApc->NormalContext = pInfo;
					//MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
				
					st = ObOpenObjectByPointer(
					Process,
					0,
					NULL,
					PROCESS_ALL_ACCESS,
					*PsProcessType,
					KernelMode,
					&Processhandle
					);
					if (st != STATUS_SUCCESS)
					{
					DbgPrint("获取句柄失败！\n");
					}
					st = ZwAllocateVirtualMemory(Processhandle, (PVOID*)&pMappedAddress, 0, &LENGTH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					RtlCopyMemory(pMappedAddress, shellcode32, LENGTH);
					if (st != STATUS_SUCCESS)

					{
						DbgPrint("申请内存失败！");
						IoFreeMdl(pMdl);
					}
					else
					{
						DbgPrint("%lx", pMappedAddress);

					}
					
					KeUnstackDetachProcess(&ApcStAte);
					/*KeInitializeEvent(&(pInfo->Event), NotificationEvent, TRUE);
					KeClearEvent(&(pInfo->Event));
					if (KeInsertQueueApc(pApc, 0, 0, 0))
					{
					interval.QuadPart = -10000;//DELAY_ONE_MILLISECOND;
					interval.QuadPart *= 1000;
					st = KeWaitForSingleObject(&(pInfo->Event), Executive, KernelMode, 0, &interval);
					while (st != STATUS_SUCCESS){

					}
					FREE(pApc);

					}
					else
					{
					FREE(pApc);

					}*/
					//FREE(pApc);
					//FREE(pInfo);
					//MmUnlockPages(pMdl);
					break;
				}
				/*st = ObOpenObjectByPointer(
					ethrd,
					0,
					NULL,
					NULL,
					NULL,
					KernelMode,
					&ethrdhandle
					);*/
				/*if (st != STATUS_SUCCESS)
				{
					DbgPrint("获取句柄失败！\n");
					return st;
				}*/
				
			//}
		}
			}
	}
	__except (1)
	{

	}
	return st;
}
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
	DbgPrint("驱动卸载成功!\n");
}
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	INT pIoBuffer[3] = {0};
	ULONG uInSize;
	ULONG uOutSize;
	DWORD32 len = 0, idGame = 0, add = 0;
	DWORD32 ret = 0;
	PEPROCESS process = NULL;
	PVOID XXXX;
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	//得到输入缓冲区大小
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//得到输出缓冲区大小
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID OutBuffer = pIrp->UserBuffer;
	switch (uIoControlCode)
	{
	case Read:
		;
		RtlCopyMemory(&idGame, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 0, 4);
		RtlCopyMemory(&add, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 4, 4);
		RtlCopyMemory(&len, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 8, 4);
		DbgPrint("读取进程PID为: %ld 地址为:%P 读取长度为:%d", idGame, add, len);
		Pobjecint buffer = MALLOC_NPP(sizeof(objecint));
		BOOLEAN b = 0;
		if (buffer != NULL)
		{
			status = PsLookupProcessByProcessId((HANDLE)idGame, &process);
		}
		if (status == STATUS_SUCCESS)
		{

				__try
				{
					b = ForceReadProcessMemory2(process, add, len, buffer);
					
					if (b == 0)
					{
						DbgPrint("读取失败...\n");
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					;
					//ObDereferenceObject(process);
					//ExFreePool(buffer);
				}
			}
	    	DbgPrint("读取的数据为:%x\n", buffer->information);
	    	RtlCopyMemory(OutBuffer, buffer, len);
			ObDereferenceObject(process);
			FREE(buffer);
			break;

	case Write:
		;
		RtlCopyMemory(&idGame, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 0, 4);
		RtlCopyMemory(&add, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 4, 4);
		RtlCopyMemory(&len, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 8, 4);
		RtlCopyMemory(&ret, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 12, len);
		DbgPrint("写入进程PID为: %ld 地址为:%P 读取长度为:%d 读取的数据为:%08X", idGame, add, len,ret);
		Pobjecint buffers = MALLOC_NPP(sizeof(objecint));

		if (buffers != NULL)
		{
			status = PsLookupProcessByProcessId((HANDLE)idGame, &process);
		}
		if (status == STATUS_SUCCESS)
		{
			__try
			{
				ForceWriteProcessMemory2(process, add, len, &ret);
				
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				;
				//ObDereferenceObject(process);
				//ExFreePool(buffers);
				
			}

			DbgPrint("写入的数据为:%x\n", ret);
			RtlCopyMemory(OutBuffer, &ret, len);
			ObDereferenceObject(process);
			FREE(buffers);
			break;
		}
	case ReadTEXT:
		;
		RtlCopyMemory(&idGame, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 0, 4);
		RtlCopyMemory(&add, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 4, 4);
		RtlCopyMemory(&len, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 8, 4);
		DbgPrint("读取进程PID为: %ld 地址为:%P 读取长度为:%d", idGame, add, len);
		PVOID bufferz = MALLOC_NPP(50);
		if (bufferz != NULL)
		{
			status = PsLookupProcessByProcessId((HANDLE)idGame, &process);
		}
		if (status == STATUS_SUCCESS)
		{
			__try
			{
				b = ForceReadProcessMemory2(process, add, len, bufferz);
				if (b == 0)
				{
					DbgPrint("读取失败...\n");
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				;
				//ObDereferenceObject(process);
				//ExFreePool(buffer);
			}

			DbgPrint("读取文本的数据为:%S\n", bufferz);
			RtlCopyMemory(OutBuffer, bufferz, len);
			ObDereferenceObject(process);
			FREE(bufferz);
			break;
		}
	case MDL_shellcode:
		;

		RtlCopyMemory(&idGame, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 0, 4);
		shellcode_MDL bufferss = MALLOC_NPP(sizeof(shellcode32));
		if (bufferss != NULL)
		{
			status = RtlCopyMemory(bufferss, shellcode32, sizeof(shellcode32));
		}
		else
		{
			return  status;
		}
		status = PsLookupProcessByProcessId((HANDLE)idGame, &process);

		if (status == STATUS_SUCCESS)
		{
			__try
			{

				b = APC_MDL_Shellcode_1(process, bufferss);
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				;
				//ObDereferenceObject(process);
				//ExFreePool(buffer);
			}
	}
	case MDL_shellcode2:
	
		;
		ULONG i;
		RtlCopyMemory(&idGame, (char*)pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer + 0, 4);
		//InitializeOffset();
//		InjectThread(idGame);


		status = PsLookupProcessByProcessId((HANDLE)idGame, &process);
		for (i = 8; i < 1000000; i = i + 4)
		{
			PETHREAD ethrd = LookupThread((HANDLE)i);
			if (ethrd != NULL)
			{
				PEPROCESS eproc = IoThreadToProcess(ethrd);
				ObDereferenceObject(ethrd);
				if (eproc == process)
				{
					/*ULONGLONG I = (ULONGLONG)ethrd + 0x4c;
					if (((pmdzz)I)->Alertable)
					{
						DbgPrint("是可警醒的线程\n");*/
						APC_MDL_Shellcode_2(ethrd, pMappedAddress, process);
						break;
					}
					/*else{
						DbgPrint("不是警醒的线程，继续寻找\n");
					}*/

				}

			}
	}

	status = STATUS_SUCCESS;
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	DbgPrint("IRP_MJ_CREATE\n");
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	//cbk_deinit();
	DbgPrint("IRP_MJ_CLOSE\n");
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
		NTSTATUS status = STATUS_SUCCESS;
		UNICODE_STRING ustrLinkName;
		UNICODE_STRING ustrDevName;
		PDEVICE_OBJECT pDevObj;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose; 
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
		DriverObject->DriverUnload = DriverUnload;
		RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
		status = IoCreateDevice(DriverObject, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
		//cbk_init();
		if (!NT_SUCCESS(status))
		{
			return status;
		}
		status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
		DriverObject->DeviceObject = pDevObj;
		if (!NT_SUCCESS(status))
		{
			IoDeleteDevice(DriverObject);

			return status;
		}
		DbgPrint("驱动%S创建成功!\n", ustrDevName.Buffer);

		return STATUS_SUCCESS;
}
