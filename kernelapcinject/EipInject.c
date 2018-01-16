#include <Ntifs.h>
#include <ntddk.h>
#include"ctl.h"


UCHAR g_EipShellCode[] = { 
	0x60,
	0x6A, 0x44,
	0xA1, 0x00, 0x60, 0x41, 0x00,
	0x50,
	0x8B, 0x0D, 0x00, 0x60, 0x41, 0x00,
	0x51,
	0x6A, 0x00,
	0xFF, 0x15, 0x04, 0x71, 0x41, 0x00,
	0x61,
	0xE9,0xCC,0xCC,0xCC,0xCC
};

//中继函数定义
PSSUSPENDTHREAD		sysPsSuspendThread		= NULL;
KERESUMETHREAD		sysKeResumeThead		= NULL;
PSGETCONTEXTTHREAD	sysPsGetContextThread	= NULL;
PSSETCONTEXTTHREAD	sysPsSetContextThread	= NULL;
//结构偏移定义
//eprocess到Thread List 偏移
ULONG EPROCESS_TO_THREADLISTHEAD_OFFSET		= 0;
//kthread到线程入口
ULONG KTHREAD_TO_THREADLISTENTRY_OFFSET		= 0;
//kthread到teb
ULONG KTHREAD_TO_TEB_OFFSET					= 0;
//
//注入代码
/*NTSTATUS StartInject(HANDLE PID)
{
	NTSTATUS Status = STATUS_SUCCESS;
	//线程句柄
	HANDLE hThread = NULL;
	PETHREAD pEthreadObj = NULL;
	//创建线程
	Status = PsCreateSystemThread(&hThread,0,NULL,NULL,NULL,InjectThread,(PVOID)pDevExt);
	if(!NT_SUCCESS(Status))
	{
		KdPrint(("Get Driver Inject Thread Failed!%x\r\n",Status));
		return Status;
	}
	
	//调试等待
	Status = ObReferenceObjectByHandle(hThread,NULL,*PsThreadType,KernelMode,(PVOID*)&pEthreadObj,NULL);
	KeWaitForSingleObject((PVOID)pEthreadObj,Executive,KernelMode,FALSE,NULL);
	
	//关闭线程句柄
	ZwClose(hThread);
	return Status;
}*/

//初始化偏移
BOOLEAN InitializeOffset()
{
	
	BOOLEAN bIsOk = FALSE;

	ULONGLONG uNtSuspendThread = 0;
	ULONGLONG uNtResumeThread = 0;
	ULONGLONG uNtGetContextThread = 0;
	ULONGLONG uNtSetContextThread = 0;
	ULONGLONG uNtQueryInformationThread = 0;

			
			uNtSuspendThread = GetFuncAddr(379);
			uNtResumeThread = GetFuncAddr(79);
			uNtGetContextThread = GetFuncAddr(202);
			uNtSetContextThread = GetFuncAddr(336);
			uNtQueryInformationThread = GetFuncAddr(34);
			sysPsSuspendThread = (PSSUSPENDTHREAD)(uNtSuspendThread + 0xB4);
			sysKeResumeThead = (KERESUMETHREAD)(*(ULONG*)(uNtResumeThread + 0x79) + 0x5 + uNtResumeThread + 0x78);
			sysPsGetContextThread = (PSGETCONTEXTTHREAD)(*(ULONG*)(uNtGetContextThread + 0x7A)+ 0x5 + uNtGetContextThread + 0x79);
			sysPsSetContextThread = (PSSETCONTEXTTHREAD)(*(ULONG*)(uNtSetContextThread + 0x64) + 0x5 + uNtSetContextThread + 0x63);
			EPROCESS_TO_THREADLISTHEAD_OFFSET = 0x300;
			KTHREAD_TO_THREADLISTENTRY_OFFSET = 0x2f8;
			KTHREAD_TO_TEB_OFFSET = 0xb8;
			bIsOk = TRUE;
	

	return bIsOk;
}

//注入的线程
VOID InjectThread(HANDLE PID)
{
	//得到设备扩展信息
	//PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pThreadContext;
	//注入的进程EPROCESS 和 ETHREAD结构
	PEPROCESS pEprocess = NULL;
	PETHREAD pEthread = NULL;
	//注入的进程ID
	HANDLE hProcessId = PID;
	//返回值
	NTSTATUS Status;
	//目标线程的上下文结构
	//CONTEXT_WOW64 ThreadContext = { 0x00010000L | 0x00000001L };

	//用户线程的上下文
	PCONTEXT_WOW64 pUserContext = NULL;
	//映射到用户空间中的上下文结构
	PMDL pContextMdl = NULL;
	ULONG i;
	Status = PsLookupProcessByProcessId((HANDLE)PID, &pEprocess);
	for (i = 8; i < 1000000; i = i + 4)
	{
		PETHREAD ethrd = LookupThread((HANDLE)i);

		if (ethrd != NULL)
		{

			PEPROCESS eproc = IoThreadToProcess(ethrd);
			ObDereferenceObject(ethrd);
			if (eproc == pEprocess)
			{
				//开始操作了,首先，挂起目标线程，防止它乱跑
				if (!NT_SUCCESS(sysPsSuspendThread(pEthread, NULL)))
				{
					KdPrint(("SuspendThead Failed!\r\n"));
					PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}

				//然后获取目标的线程运行上下文
				/*pContextMdl = IoAllocateMdl(&ThreadContext, sizeof(CONTEXT_WOW64), FALSE, FALSE, NULL);
				if (!MmIsAddressValid(pContextMdl))
				{
				KdPrint(("Allocate UserContext Mdl Failed!\r\n"));
				PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}

				//锁定一下,并且我们还要在内核下修改
				MmProbeAndLockPages(pContextMdl,KernelMode,IoWriteAccess);*/

				//附加到目标进程上下文中
				KeAttachProcess(pEprocess);

				//把这个上下文结构映射到用户空间中
				/*pUserContext = MmMapLockedPagesSpecifyCache(pContextMdl,UserMode,MmCached,NULL,FALSE,NormalPagePriority);
				if (!pUserContext)
				{
				KdPrint(("Map Context Memory Page Failed!\r\n"));
				//解除映射
				MmUnmapLockedPages(pUserContext,pContextMdl);
				//解除挂接
				KeDetachProcess();
				//解除锁定
				MmUnlockPages(pContextMdl);
				//释放MDL
				IoFreeMdl(pContextMdl);
				//恢复线程运行<因此此例程使用了寄存器传参，所以用汇编了>
				sysKeResumeThead(pEthread);
				PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}*/

				//获取上下文
				Status = sysPsGetContextThread(pEthread, pUserContext, UserMode);
				if (!NT_SUCCESS(Status))
				{
					KdPrint(("Get Context Failed!\r\n"));
					//解除映射
					MmUnmapLockedPages(pUserContext, pContextMdl);
					//解除挂接
					KeDetachProcess();
					//解除锁定
					MmUnlockPages(pContextMdl);
					//释放MDL
					IoFreeMdl(pContextMdl);
					//恢复线程运行<因此此例程使用了寄存器传参，所以用汇编了>
					sysKeResumeThead(pEthread);
					PsTerminateSystemThread(Status);
				}

				//到了这一步，说明我们获取目标线程的上下文成功了!接下来初始化ShellCode


				//用户执行地址
				ULONG* pUserActiveAddr = (ULONG*)AllocateUserVirtualMemory(pEprocess);

				//地址分配检查
				if (!MmIsAddressValid((PVOID)pUserActiveAddr))
				{
					KdPrint(("Allocate Mdl Failed!\r\n"));
					//解除映射
					MmUnmapLockedPages(pUserContext, pContextMdl);
					//解除挂接
					KeDetachProcess();
					//解除锁定
					MmUnlockPages(pContextMdl);
					//释放MDL
					IoFreeMdl(pContextMdl);
					//恢复线程运行
					sysKeResumeThead(pEthread);
					PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}
				KdPrint(("Map User Actinve Address:0x%08X\r\n", pUserActiveAddr));

				//接下来就是修正返回地址
				/*for(ULONG i = 0; i < sizeof(g_EipShellCode); i++)
				{
				if (*(UCHAR*)((ULONG)pUserContext + i) == 0xe9 &&
				*(UCHAR*)((ULONG)pUserContext + i + 1) == 0xcc &&
				*(UCHAR*)((ULONG)pUserContext + i + 2) == 0xcc &&
				*(UCHAR*)((ULONG)pUserContext + i + 3) == 0xcc &&
				*(UCHAR*)((ULONG)pUserContext + i + 4) == 0xcc)
				{
				//找到返回地址了,我们需要修正它
				*(ULONG*)((ULONG)pUserContext + i + 1) = ThreadContext.Eip - ((ULONG)pUserContext + i) - 5;
				break;
				}
				}*/

				//再次设置线程运行上下文，让其指向我们ShellCode映射的用户地址
				//ThreadContext.ContextFlags = CONTEXT_CONTROL;
				pUserContext->Eip = (ULONG32)pUserActiveAddr;

				//然后调用设置上下文函数
				Status = sysPsSetContextThread(pEthread, (PCONTEXT_WOW64)pUserContext, UserMode);
				//判断设置是否成功
				if (!NT_SUCCESS(Status))
				{
					KdPrint(("SetThread Failed!\r\n"));
					//释放虚拟内存(此时不能释放，因为ShellCode还没有运行完毕，释放的话注入进程会奔溃，所以不释放了)
					//	ZwFreeVirtualMemory()
					//解除映射
					MmUnmapLockedPages(pUserContext, pContextMdl);
					//解除挂接
					KeDetachProcess();
					//解除锁定
					MmUnlockPages(pContextMdl);
					//释放MDL
					IoFreeMdl(pContextMdl);
					//恢复线程运行
					sysKeResumeThead(pEthread);
					PsTerminateSystemThread(Status);
				}

				//到了这一步，我们就大功告成了，现在我们解除附加，同时恢复目标线程运行，等待些许时间后我们再释放资源即可

				//恢复线程<恢复它运行>
				sysKeResumeThead(pEthread);
				//注入成功,打印提示信息
				KdPrint(("Inject Success!Pid:%d", hProcessId));
				//回收资源
				//解除映射
				MmUnmapLockedPages(pUserContext, pContextMdl);
				//解除锁定
				MmUnlockPages(pContextMdl);
				//释放MDL
				IoFreeMdl(pContextMdl);
				//解除挂接
				KeDetachProcess();
				//用户空间的虚拟内存如何解决<这个因为申请的虚拟内存在进程退出的时候会自动释放，所以我们不需要管这个，如果想要完美的话，同样可以在这里等待几秒钟后等到ShellCode执行完毕后再释放也是一样的>

				PsTerminateSystemThread(STATUS_SUCCESS);
			}

		}
	}
}
//查找指定进程中的用户线程对象
PETHREAD FindEthreadByEProcess(IN ULONG uProcess)
{
	//得到EPROCESS +0x188 ThreadListHead   : _LIST_ENTRY	win7
	PLIST_ENTRY pTheadListHead = (PLIST_ENTRY)(uProcess + EPROCESS_TO_THREADLISTHEAD_OFFSET);
	//得到第一个位置的元素
	PLIST_ENTRY pThreadListEntry = pTheadListHead->Flink;
	//减去偏移，得到KTHREAD(ETHREAD)数据结构
	while (pTheadListHead != pThreadListEntry)
	{
		//遍历所有的内核线程结构 win7 
		PKTHREAD pCurKthread = (PKTHREAD)((ULONGLONG)(pThreadListEntry)-KTHREAD_TO_THREADLISTENTRY_OFFSET);
		//KTHREAD +0x088 Teb             	      : Ptr32 Void win7
		//检测TEB看是否是用户线程，如果不是用户线程,继续遍历下一个
		if (0x00 < (*(ULONG*)((ULONGLONG)pCurKthread + KTHREAD_TO_TEB_OFFSET)) <= 0x80000000)
		{
			KdPrint(("Inject ETHREAD Struct Address:0x%08X",(ULONG)pCurKthread));
			//如果这个条件满足，说明是用户线程，返回即可
			return (PETHREAD)pCurKthread;
		}
		else
		{
			//否则遍历下一个
			pThreadListEntry = pThreadListEntry->Flink;
		}
	}
	KdPrint(("Not the Process of user Thread!\r\n"));
	//如果运行到了这里说明此进程中没有用户线程
	return (PETHREAD)0x00;

}

//申请用户内存
PVOID AllocateUserVirtualMemory(PEPROCESS pErpocess)
{
	//将EPROCESS转成句柄
	HANDLE hProcess = NULL;
	NTSTATUS Status = ObOpenObjectByPointer((PVOID)pErpocess,0,NULL,PROCESS_ALL_ACCESS,*PsProcessType,KernelMode,&hProcess);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Get Handle Failed!%x\r\n",Status));
		return NULL;
	}
	ObDereferenceObject(pErpocess);
	
	ULONG pBaseAddr = NULL;
	ULONG uCodeSize = sizeof(g_EipShellCode)+2;
	Status = ZwAllocateVirtualMemory(hProcess,(PVOID*)&pBaseAddr,0,&uCodeSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Get User Memory Failed!%x\r\n",Status));
		return NULL;
	}

	//拷贝ShellCode
	RtlCopyMemory((PVOID)pBaseAddr,g_EipShellCode,sizeof(g_EipShellCode));
	//填充Dll路径
	//RtlCopyMemory((PVOID)(pBaseAddr + sizeof(g_EipShellCode)),DllPath,uCodeSize - sizeof(g_EipShellCode));
	//返回申请到的地址
	return (PVOID)pBaseAddr;
}