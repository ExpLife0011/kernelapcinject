#include <Ntifs.h>
#include <ntddk.h>//创建用户栈
#define xAlloc(_s)        ExAllocatePool(NonPagedPool, _s)
typedef struct _SYSTEM_PROCESSES
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
} _SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;
//创建线程
typedef struct  _BASE_CREATE_THREAD
{
	HANDLE hThread;
	CLIENT_ID ClientId;
}BASE_CREATE_THREAD;
typedef struct  _BASE_CREATE_PROCESS
{
	HANDLE Process;
	CLIENT_ID ClientId;
}BASE_CREATE_PROCESS;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,// 0 Y N
	SystemProcessorInformation,// 1 Y N
	SystemPerformanceInformation,// 2 Y N
	SystemTimeOfDayInformation,// 3 Y N
	SystemNotImplemented1,// 4 Y N // SystemPathInformation
	SystemProcessesAndThreadsInformation,// 5 Y N
	SystemCallCounts,// 6 Y N
	SystemConfigurationInformation,// 7 Y N
	SystemProcessorTimes,// 8 Y N
	SystemGlobalFlag,// 9 Y Y
	SystemNotImplemented2,// 10 YN // SystemCallTimeInformation
	SystemModuleInformation,// 11 YN
	SystemLockInformation,// 12 YN
	SystemNotImplemented3,// 13 YN // SystemStackTraceInformation
	SystemNotImplemented4,// 14 YN // SystemPagedPoolInformation
	SystemNotImplemented5,// 15 YN // SystemNonPagedPoolInformation
	SystemHandleInformation,// 16 YN
	SystemObjectInformation,// 17 YN
	SystemPagefileInformation,// 18 YN
	SystemInstructionEmulationCounts,// 19 YN
	SystemInvalidInfoClass1,// 20
	SystemCacheInformation,// 21 YY
	SystemPoolTagInformation,// 22 YN
	SystemProcessorStatistics,// 23 YN
	SystemDpcInformation,// 24 YY
	SystemNotImplemented6,// 25 YN // SystemFullMemoryInformation
	SystemLoadImage,// 26 NY // SystemLoadGdiDriverInformation
	SystemUnloadImage,// 27 NY
	SystemTimeAdjustment,// 28 YY
	SystemNotImplemented7,// 29 YN // SystemSummaryMemoryInformation
	SystemNotImplemented8,// 30 YN // SystemNextEventIdInformation
	SystemNotImplemented9,// 31 YN // SystemEventIdsInformation
	SystemCrashDumpInformation,// 32 YN
	SystemExceptionInformation,// 33 YN
	SystemCrashDumpStateInformation,// 34 YY/N
	SystemKernelDebuggerInformation,// 35 YN
	SystemContextSwitchInformation,// 36 YN
	SystemRegistryQuotaInformation,// 37 YY
	SystemLoadAndCallImage,// 38 NY // SystemExtendServiceTableInformation
	SystemPrioritySeparation,// 39 NY
	SystemNotImplemented10,// 40 YN // SystemPlugPlayBusInformation
	SystemNotImplemented11,// 41 YN // SystemDockInformation
	SystemInvalidInfoClass2,// 42 // SystemPowerInformation
	SystemInvalidInfoClass3,// 43 // SystemProcessorSpeedInformation
	SystemTimeZoneInformation,// 44 YN
	SystemLookasideInformation,// 45 YN
	SystemSetTimeSlipEvent,// 46 NY
	SystemCreateSession,// 47 NY
	SystemDeleteSession,// 48 NY
	SystemInvalidInfoClass4,// 49
	SystemRangeStartInformation,// 50 YN
	SystemVerifierInformation,// 51 YY
	SystemAddVerifier,// 52 NY
	SystemSessionProcessesInformation// 53 YN
} SYSTEM_INFORMATION_CLASS;
typedef struct _INITIAL_TEB {
	struct {
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;
typedef struct _CSR_API_MSG
{
	PORT_MESSAGE PortMessage;	//	/*0x00*/
	union
	{
		BASE_API_CONNECTINFO ConnectionInfo;		//Base Api	/*0x18*/

		struct
		{
			CSR_CAPTURE_HEADER*	CaptureData;		/*0x18*/
			ULONG		ApiNumber;			/*0x1C*/
			NTSTATUS	Status;	//ReturnValue;		/*0x20*/	
			ULONG		Reserved;							/*0x24*/
			union
			{

				BASE_CREATE_THREAD  CreateThread;		//apiNumber = 0		/*0x28*/
				BASE_CREATE_PROCESS CreateProcess;		//apiNumber = 0

				//这里只是为了占位
				ULONG_PTR ApiMessageData[39];
			}Data;
		};
	};
}CSR_API_MSG;

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
#define INIT_ZW_API(_s)  GetZwFuncAddress(_s)

NTSTATUS _BaseCreateStack(IN HANDLE hProcess,OUT INITIAL_TEB* pInitialTeb)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	_SYSTEM_PROCESSES * pSysBasicInfo = NULL;
	ULONG_PTR ulSize = 0;

	ULONG_PTR StackReserve = 0;
	ULONG_PTR StackCommit = 0;
	ULONG_PTR Stack = 0;
	BOOLEAN UseGuard = FALSE;
	ULONG_PTR GuardPageSize = 0;
	ULONG Dummy = 0;

	PVOID	fnZwProtectVirtualMemory = NULL;

	do 
	{
		if ( (NULL == hProcess) || (NULL == pInitialTeb) )
		{
			xDebugA(("[-] 参数不正确! \n"));
			break;
		}

		fnZwProtectVirtualMemory = INIT_ZW_API(77);//ZwProtectVirtualMemory
		if (NULL == fnZwProtectVirtualMemory)
		{
			xDebugA(("[-] 获取 fnZwProtectVirtualMemory 失败! \n"));
			break;
		}
	
		pSysBasicInfo = (_SYSTEM_PROCESSES*)xAlloc(sizeof(_SYSTEM_PROCESSES));
		if (NULL == pSysBasicInfo)
		{
			xDebugA(("[-]内存分配失败! \n"));
			break;
		}

		//获取内存信息
		Status = ZwQuerySystemInformation(SystemBasicInformation,
			pSysBasicInfo,
			sizeof(_SYSTEM_PROCESSES),
			&ulSize
			);

		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-] 获取系统基本信息失败! %s \n" , Status2Str(Status) ));
			break;
		}

		//系统默认的栈信息
		StackReserve = SIZE_MB * 1;
		StackCommit = SIZE_KB * 64;;

		//栈提交大小是否大于栈保存的大小
		if (StackCommit >= StackReserve)
		{
			//增大保存的大小,1MB对齐
			StackReserve = ROUND_UP(StackCommit,1024 * 1024);
		}
		
		//对齐到页面大小
		StackReserve = ROUND_UP(StackReserve,pSysBasicInfo->AllocationGranularity);
		StackCommit = ROUND_UP(StackCommit,pSysBasicInfo->PageSize);

		//为栈分配保留的内存
		Status = ZwAllocateVirtualMemory(hProcess,
			(PVOID*)&Stack,
			0,
			&StackReserve,
			MEM_RESERVE,
			PAGE_READWRITE
			);

		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-]为栈保留内存 失败!  %s \n " ,Status2Str(Status) ));
			break;
		}
		
		//初始化TEB
		pInitialTeb->PreviousStackBase = NULL;
		pInitialTeb->PreviousStackLimit = NULL;
		pInitialTeb->AllocatedStackBase = (PVOID)Stack;
		pInitialTeb->StackBase = (PVOID)(Stack + StackReserve);

		//更新栈的位置
		Stack += StackReserve - StackCommit;

		//判断是否需要栈保护页来实现栈的自动增长
		if (StackReserve > StackCommit)
		{
			//空出一页作为保护页
			Stack -= pSysBasicInfo->PageSize;
			StackCommit += pSysBasicInfo->PageSize;
			UseGuard = TRUE;
		}


		//真正的分配栈内存
		Status = ZwAllocateVirtualMemory(hProcess,
			(PVOID*)&Stack,
			0,
			&StackCommit,
			MEM_COMMIT,
			PAGE_READWRITE
			);

		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-]为栈分配内存 失败!  %s \n " ,Status2Str(Status) ));
			break;
		}

		//栈的限制大小
		pInitialTeb->StackLimit = (PVOID)Stack;

		//创建保护页
		if (UseGuard)
		{
			/* Attempt maximum space possible */
			GuardPageSize = pSysBasicInfo->PageSize;

			Status = CALL_API(ZwProtectVirtualMemory)(hProcess,
				(PVOID*)&Stack,
				&GuardPageSize,
				PAGE_GUARD | PAGE_READWRITE,
				&Dummy
				);

			if ( !NT_SUCCESS(Status))
			{
				xDebugA(("[-]为栈创建保护页 失败!  %s \n " ,Status2Str(Status) ));
				break;
			}

			/* Update the Stack Limit keeping in mind the Guard Page */
			pInitialTeb->StackLimit = (PVOID)((ULONG_PTR)pInitialTeb->StackLimit + GuardPageSize);
		}

	} while (FALSE);

	xFree(pSysBasicInfo);

	return Status;
}

NTSTATUS _BaseInitializeContext
(
	IN PEPROCESS Process,
	IN BOOLEAN bWow64,
	IN PCONTEXT Context,
	IN PVOID Parameter,
	IN PVOID StartAddress,
	IN PVOID StackAddress
)
{
	ULONG ulThunkSize = 0;
	PVOID pLocalThunk = NULL;		//内核的Thunk数据
	PVOID pRemoteThunk = NULL;	//用户态的Thunk地址
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ULONG ulInfoSize = 0;
	
	
	do 
	{
		
#ifdef _WIN64
		if (bWow64)
		{
			pLocalThunk = _BaseThreadStartThunk_x86;
			ulThunkSize = sizeof(_BaseThreadStartThunk_x86);
		}
		else
		{
			pLocalThunk = _BaseThreadStartThunk_x64;
			ulThunkSize = sizeof(_BaseThreadStartThunk_x64);
		}
		
#else
		pLocalThunk = _BaseThreadStartThunk_x86;
		ulThunkSize = sizeof(_BaseThreadStartThunk_x86);
#endif
		
		Status = kVirtualAllocEx(Process,
			&pRemoteThunk,
			ulThunkSize,
			MEM_COMMIT|MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
			);
		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-] 分配 thunk内存失败! \n"));
			break;
		}
		
		Status = kVirtualWrite(Process,
			pRemoteThunk,
			pLocalThunk,
			ulThunkSize,
			&ulInfoSize
			);
		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-] 写入 thunk到ring3失败! \n"));
			break;
		}
		
		
#ifdef _WIN64
		
		/* Setup the Initial Win32 Thread Context */
		Context->Rax = (ULONG_PTR)StartAddress;
		Context->Rbx = (ULONG_PTR)Parameter;
		Context->Rsp = (ULONG_PTR)StackAddress;
		/* The other registers are undefined */
		
		/* Setup the Segments */
		Context->SegGs = 0x0028 | 0x0003;
		Context->SegEs = 0x0028 | 0x0003;
		Context->SegDs = 0x0028 | 0x0003;
		Context->SegCs = 0x0030 | 0x0003;
		Context->SegSs = 0x0028 | 0x0003;
		Context->SegFs = 0x0050 | 0x0003;
		
		/* Set the EFLAGS */
		Context->EFlags = 0x3000; /* IOPL 3 */

		/* Set the Context Flags */
		Context->ContextFlags = CONTEXT_FULL;

		/* Give it some room for the Parameter */
		Context->Rsp -= sizeof(PVOID);

		Context->Rip = (ULONG_PTR)pRemoteThunk;	
#else
		
		/* Setup the Initial Win32 Thread Context */
		Context->Eax = (ULONG)StartAddress;
		Context->Ebx = (ULONG)Parameter;
		Context->Esp = (ULONG)StackAddress;
		/* The other registers are undefined */
		
		/* Setup the Segments */
		Context->SegFs = 0x38;
		Context->SegEs = 0x20;
		Context->SegDs = 0x20;
		Context->SegCs = 0x18;
		Context->SegSs = 0x20;
		Context->SegGs = 0;

		/* Set the EFLAGS */
		Context->EFlags = 0x3000; /* IOPL 3 */
		
		/* Set the Context Flags */
		Context->ContextFlags = CONTEXT_FULL;
		
		/* Give it some room for the Parameter */
		Context->Esp -= sizeof(PVOID);
		
		Context->Eip = (ULONG)pRemoteThunk;
#endif

		xDebugA(("[*] ThreadTrunk = 0x%p \n" , pRemoteThunk ));
		
		Status = STATUS_SUCCESS;
		
	} while (FALSE);


	if (!NT_SUCCESS(Status))
	{
		if (NULL != pRemoteThunk)
		{
			kVirtualFree(Process,pRemoteThunk);
			pRemoteThunk = NULL;
		}
	}

	return Status;
}

//创建用户态线程
NTSTATUS kCreateUserModeThread(
	IN PEPROCESS Process,
	IN BOOLEAN bCreateSuspended,
	IN void* pStartAddress,	//用户态地址
	IN PVOID pParameter,		//用户态地址
    IN OUT HANDLE* phThreadHandle,
    IN OUT HANDLE* phThreadId
)
{
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = {0};
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	CONTEXT ThreadContext = {0};
	HANDLE hThread = NULL;
	CLIENT_ID ClientId = {0};
	INITIAL_TEB UserStack = {0};

	CSR_API_MSG ApiMessage = {0};
    BASE_CREATE_THREAD* pCreateThreadRequest = &ApiMessage.Data.CreateThread;

	ULONG SuspendCount = 0;
	SIZE_T Dummy = 0;
	BOOLEAN bWow64 = FALSE;

	do 
	{
		if (  (NULL == Process) || (NULL == pStartAddress) )
		{
			xDebugA(("[-] 参数不正确! \n"));
			break;
		}

		if (NULL == INIT_ZW_API(ZwCreateThread) )
		{
			xDebugA(("[-] 获取 ZwCreateThread 地址失败! \n"));
			break;
		}

		if (NULL == INIT_ZW_API(ZwResumeThread) )
		{
			xDebugA(("[-] 获取 ZwResumeThread 地址失败! \n"));
			break;
		}

		if (NULL == INIT_ZW_API(ZwTerminateThread) )
		{
			xDebugA(("[-] 获取 ZwTerminateThread 地址失败! \n"));
		}


#ifdef _WIN64
		kIsWow64Process(Process,&bWow64);
#endif
		

		Status = ObOpenObjectByPointer(Process,
			OBJ_KERNEL_HANDLE,
			NULL,
			PROCESS_ALL_ACCESS,
			NULL,
			KernelMode,
			&hProcess
			);

		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-] 打开进程失败! %s \n" , Status2Str(Status) ));
			break;
		}

		//创建一个用户态的栈
		Status = _BaseCreateStack(hProcess,&UserStack);
		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-] Creat UserMode Stack faild %s \n" , Status2Str(Status)  ));
			break;
		}
		
		//初始化新线程的上下文
		_BaseInitializeContext(
			Process,
			bWow64,
			&ThreadContext,
			pParameter,
			pStartAddress,
			UserStack.StackBase
			);

		InitializeObjectAttributes(
			&ObjectAttributes,
			NULL,
			OBJ_KERNEL_HANDLE,
			NULL,
			NULL
		);

		ClientId.UniqueProcess = PsGetProcessId(Process);
	
		//创建线程,
		Status = CALL_API(ZwCreateThread)(
			&hThread,
			THREAD_ALL_ACCESS,
			&ObjectAttributes,
			hProcess,
			&ClientId,
			&ThreadContext,
			&UserStack,
			TRUE	//挂起
		);

		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-] 创建线程失败 %s \n" , Status2Str(Status) ));
			break;
		}

		pCreateThreadRequest->ClientId.UniqueProcess = ClientId.UniqueProcess;
		pCreateThreadRequest->ClientId.UniqueThread = ClientId.UniqueThread;
		pCreateThreadRequest->hThread = hThread;

		//通知csrss,非常重要,
		//这个操作涉及到搜索句柄,耗时 80 ~ 230 ms不等.
		Status = kInformCsrss(Process,
			(CSR_API_MSG*)&ApiMessage,
			CSR_CREATE_API_NUMBER( BASESRV_SERVERDLL_INDEX,BasepCreateThread),
			sizeof(BASE_CREATE_THREAD)
			);
		if (!NT_SUCCESS(Status))
		{
			xDebugA(("[-] 通知csrss 失败 %s \n" , Status2Str(Status) ));
			break;
		}

		//恢复线程的执行.
		if (!bCreateSuspended)
		{
			CALL_API(ZwResumeThread)(hThread,&SuspendCount);
		}
		
		xDebugA(("[+] 创建线程成功, Pid: %d Tid: %d hThread: 0x%p , 起始地址: 0x%p \n" ,
				ClientId.UniqueProcess,
				ClientId.UniqueThread,
				hThread,
				pStartAddress
			));

		Status = STATUS_SUCCESS;
	} while (FALSE);

	if (!NT_SUCCESS(Status))
	{
		if (NULL != hProcess)
		{
			NtFreeVirtualMemory(hProcess,
				&UserStack.AllocatedStackBase,
				&Dummy,
				MEM_RELEASE
			);
		}
		
		if (NULL != hThread)
		{
			if (NULL != INIT_API(ZwTerminateThread))
			{
				CALL_API(ZwTerminateThread)(hThread,Status);
			}
			
			ZwClose(hThread);
			hThread = NULL;
		}
	}

	if (NULL != hProcess)
	{
		ZwClose(hProcess);
		hProcess = NULL;
	}

	if (NULL != phThreadHandle)
	{
		*phThreadHandle = hThread;
	}
	else
	{
		if (NULL != hThread)
		{
			ZwClose(hThread);
			hThread = NULL;
		}
	}

	if (NULL != phThreadId)
	{
		*phThreadId = ClientId.UniqueThread;
	}

	return Status;
}


//使用指定进程通知Csrss,
NTSTATUS kInformCsrss(
	IN PEPROCESS Process,	
    IN OUT CSR_API_MSG* pCsrMsg,
    IN CSR_API_NUMBER ApiNumber,
    IN ULONG ArgLength
)
{
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	ULONG FixArgLength = 0;
	HANDLE hCsrPortHandle = NULL;

	do 
	{	
		if ( (NULL == Process) || (NULL == pCsrMsg)  )
		{
			xDebugA(("[-] 参数不正确! \n"));
			break;
		}

		if (kGetOSVer() >= OS_VISTA)
		{
			if (NULL == INIT_API(ZwAlpcSendWaitReceivePort))
			{
				xDebugA(("[-] 获取 ZwAlpcSendWaitReceivePort 地址失败! \n"));
				break;
			}
		}

		//获取进程的CsrPostHandle,会自动dup到当前进程
		Status = kGetProcessCsrPortHandle(Process,&hCsrPortHandle);
		if ( (!NT_SUCCESS(Status)) || (NULL == hCsrPortHandle)  )
		{
			xDebugA(("获取Port Handle 失败 %s \n" , Status2Str(Status) ));
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		FixArgLength = ArgLength;
		if ( (LONG)ArgLength < 0 )
		{
			FixArgLength = (ULONG)(-(LONG)ArgLength);
			pCsrMsg->PortMessage.u2.s2.Type = 0;
		}
		else
		{
			pCsrMsg->PortMessage.u2.ZeroInit = 0;
		}
	
		FixArgLength |= (FixArgLength << 16);

		if (kGetOSVer() < OS_VISTA)
		{
			FixArgLength +=   0x2C0010;
		}
		else
		{
			#ifdef _WIN64
				FixArgLength += 0x400018;

			#else
				FixArgLength += 0x280010;
			#endif
		
		}

		pCsrMsg->PortMessage.u1.Length = FixArgLength;

		pCsrMsg->CaptureData = NULL;

		pCsrMsg->ApiNumber = ApiNumber;

		if (kGetOSVer() < OS_VISTA)
		{	
			Status = ZwRequestWaitReplyPort(hCsrPortHandle,
				(PORT_MESSAGE*)pCsrMsg,
				(PORT_MESSAGE*)pCsrMsg
			);
		}
		else
		{
			//这个在我的虚拟机上慢的时候竟然需要300ms ! WTF
			Status = CALL_API(ZwAlpcSendWaitReceivePort)(
				hCsrPortHandle,
				0,
				(PORT_MESSAGE*)pCsrMsg,
				NULL,
				(PORT_MESSAGE*)pCsrMsg,
				NULL,
				NULL,
				NULL
			);
		}

	} while (FALSE);

	if (NULL != hCsrPortHandle)
	{
		ZwClose(hCsrPortHandle);
		hCsrPortHandle = NULL;
	}

	return Status;
}




