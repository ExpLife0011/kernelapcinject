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

//�м̺�������
PSSUSPENDTHREAD		sysPsSuspendThread		= NULL;
KERESUMETHREAD		sysKeResumeThead		= NULL;
PSGETCONTEXTTHREAD	sysPsGetContextThread	= NULL;
PSSETCONTEXTTHREAD	sysPsSetContextThread	= NULL;
//�ṹƫ�ƶ���
//eprocess��Thread List ƫ��
ULONG EPROCESS_TO_THREADLISTHEAD_OFFSET		= 0;
//kthread���߳����
ULONG KTHREAD_TO_THREADLISTENTRY_OFFSET		= 0;
//kthread��teb
ULONG KTHREAD_TO_TEB_OFFSET					= 0;
//
//ע�����
/*NTSTATUS StartInject(HANDLE PID)
{
	NTSTATUS Status = STATUS_SUCCESS;
	//�߳̾��
	HANDLE hThread = NULL;
	PETHREAD pEthreadObj = NULL;
	//�����߳�
	Status = PsCreateSystemThread(&hThread,0,NULL,NULL,NULL,InjectThread,(PVOID)pDevExt);
	if(!NT_SUCCESS(Status))
	{
		KdPrint(("Get Driver Inject Thread Failed!%x\r\n",Status));
		return Status;
	}
	
	//���Եȴ�
	Status = ObReferenceObjectByHandle(hThread,NULL,*PsThreadType,KernelMode,(PVOID*)&pEthreadObj,NULL);
	KeWaitForSingleObject((PVOID)pEthreadObj,Executive,KernelMode,FALSE,NULL);
	
	//�ر��߳̾��
	ZwClose(hThread);
	return Status;
}*/

//��ʼ��ƫ��
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

//ע����߳�
VOID InjectThread(HANDLE PID)
{
	//�õ��豸��չ��Ϣ
	//PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pThreadContext;
	//ע��Ľ���EPROCESS �� ETHREAD�ṹ
	PEPROCESS pEprocess = NULL;
	PETHREAD pEthread = NULL;
	//ע��Ľ���ID
	HANDLE hProcessId = PID;
	//����ֵ
	NTSTATUS Status;
	//Ŀ���̵߳������Ľṹ
	//CONTEXT_WOW64 ThreadContext = { 0x00010000L | 0x00000001L };

	//�û��̵߳�������
	PCONTEXT_WOW64 pUserContext = NULL;
	//ӳ�䵽�û��ռ��е������Ľṹ
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
				//��ʼ������,���ȣ�����Ŀ���̣߳���ֹ������
				if (!NT_SUCCESS(sysPsSuspendThread(pEthread, NULL)))
				{
					KdPrint(("SuspendThead Failed!\r\n"));
					PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}

				//Ȼ���ȡĿ����߳�����������
				/*pContextMdl = IoAllocateMdl(&ThreadContext, sizeof(CONTEXT_WOW64), FALSE, FALSE, NULL);
				if (!MmIsAddressValid(pContextMdl))
				{
				KdPrint(("Allocate UserContext Mdl Failed!\r\n"));
				PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}

				//����һ��,�������ǻ�Ҫ���ں����޸�
				MmProbeAndLockPages(pContextMdl,KernelMode,IoWriteAccess);*/

				//���ӵ�Ŀ�������������
				KeAttachProcess(pEprocess);

				//����������Ľṹӳ�䵽�û��ռ���
				/*pUserContext = MmMapLockedPagesSpecifyCache(pContextMdl,UserMode,MmCached,NULL,FALSE,NormalPagePriority);
				if (!pUserContext)
				{
				KdPrint(("Map Context Memory Page Failed!\r\n"));
				//���ӳ��
				MmUnmapLockedPages(pUserContext,pContextMdl);
				//����ҽ�
				KeDetachProcess();
				//�������
				MmUnlockPages(pContextMdl);
				//�ͷ�MDL
				IoFreeMdl(pContextMdl);
				//�ָ��߳�����<��˴�����ʹ���˼Ĵ������Σ������û����>
				sysKeResumeThead(pEthread);
				PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}*/

				//��ȡ������
				Status = sysPsGetContextThread(pEthread, pUserContext, UserMode);
				if (!NT_SUCCESS(Status))
				{
					KdPrint(("Get Context Failed!\r\n"));
					//���ӳ��
					MmUnmapLockedPages(pUserContext, pContextMdl);
					//����ҽ�
					KeDetachProcess();
					//�������
					MmUnlockPages(pContextMdl);
					//�ͷ�MDL
					IoFreeMdl(pContextMdl);
					//�ָ��߳�����<��˴�����ʹ���˼Ĵ������Σ������û����>
					sysKeResumeThead(pEthread);
					PsTerminateSystemThread(Status);
				}

				//������һ����˵�����ǻ�ȡĿ���̵߳������ĳɹ���!��������ʼ��ShellCode


				//�û�ִ�е�ַ
				ULONG* pUserActiveAddr = (ULONG*)AllocateUserVirtualMemory(pEprocess);

				//��ַ������
				if (!MmIsAddressValid((PVOID)pUserActiveAddr))
				{
					KdPrint(("Allocate Mdl Failed!\r\n"));
					//���ӳ��
					MmUnmapLockedPages(pUserContext, pContextMdl);
					//����ҽ�
					KeDetachProcess();
					//�������
					MmUnlockPages(pContextMdl);
					//�ͷ�MDL
					IoFreeMdl(pContextMdl);
					//�ָ��߳�����
					sysKeResumeThead(pEthread);
					PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
				}
				KdPrint(("Map User Actinve Address:0x%08X\r\n", pUserActiveAddr));

				//�����������������ص�ַ
				/*for(ULONG i = 0; i < sizeof(g_EipShellCode); i++)
				{
				if (*(UCHAR*)((ULONG)pUserContext + i) == 0xe9 &&
				*(UCHAR*)((ULONG)pUserContext + i + 1) == 0xcc &&
				*(UCHAR*)((ULONG)pUserContext + i + 2) == 0xcc &&
				*(UCHAR*)((ULONG)pUserContext + i + 3) == 0xcc &&
				*(UCHAR*)((ULONG)pUserContext + i + 4) == 0xcc)
				{
				//�ҵ����ص�ַ��,������Ҫ������
				*(ULONG*)((ULONG)pUserContext + i + 1) = ThreadContext.Eip - ((ULONG)pUserContext + i) - 5;
				break;
				}
				}*/

				//�ٴ������߳����������ģ�����ָ������ShellCodeӳ����û���ַ
				//ThreadContext.ContextFlags = CONTEXT_CONTROL;
				pUserContext->Eip = (ULONG32)pUserActiveAddr;

				//Ȼ��������������ĺ���
				Status = sysPsSetContextThread(pEthread, (PCONTEXT_WOW64)pUserContext, UserMode);
				//�ж������Ƿ�ɹ�
				if (!NT_SUCCESS(Status))
				{
					KdPrint(("SetThread Failed!\r\n"));
					//�ͷ������ڴ�(��ʱ�����ͷţ���ΪShellCode��û��������ϣ��ͷŵĻ�ע����̻ᱼ�������Բ��ͷ���)
					//	ZwFreeVirtualMemory()
					//���ӳ��
					MmUnmapLockedPages(pUserContext, pContextMdl);
					//����ҽ�
					KeDetachProcess();
					//�������
					MmUnlockPages(pContextMdl);
					//�ͷ�MDL
					IoFreeMdl(pContextMdl);
					//�ָ��߳�����
					sysKeResumeThead(pEthread);
					PsTerminateSystemThread(Status);
				}

				//������һ�������Ǿʹ󹦸���ˣ��������ǽ�����ӣ�ͬʱ�ָ�Ŀ���߳����У��ȴ�Щ��ʱ����������ͷ���Դ����

				//�ָ��߳�<�ָ�������>
				sysKeResumeThead(pEthread);
				//ע��ɹ�,��ӡ��ʾ��Ϣ
				KdPrint(("Inject Success!Pid:%d", hProcessId));
				//������Դ
				//���ӳ��
				MmUnmapLockedPages(pUserContext, pContextMdl);
				//�������
				MmUnlockPages(pContextMdl);
				//�ͷ�MDL
				IoFreeMdl(pContextMdl);
				//����ҽ�
				KeDetachProcess();
				//�û��ռ�������ڴ���ν��<�����Ϊ����������ڴ��ڽ����˳���ʱ����Զ��ͷţ��������ǲ���Ҫ������������Ҫ�����Ļ���ͬ������������ȴ������Ӻ�ȵ�ShellCodeִ����Ϻ����ͷ�Ҳ��һ����>

				PsTerminateSystemThread(STATUS_SUCCESS);
			}

		}
	}
}
//����ָ�������е��û��̶߳���
PETHREAD FindEthreadByEProcess(IN ULONG uProcess)
{
	//�õ�EPROCESS +0x188 ThreadListHead   : _LIST_ENTRY	win7
	PLIST_ENTRY pTheadListHead = (PLIST_ENTRY)(uProcess + EPROCESS_TO_THREADLISTHEAD_OFFSET);
	//�õ���һ��λ�õ�Ԫ��
	PLIST_ENTRY pThreadListEntry = pTheadListHead->Flink;
	//��ȥƫ�ƣ��õ�KTHREAD(ETHREAD)���ݽṹ
	while (pTheadListHead != pThreadListEntry)
	{
		//�������е��ں��߳̽ṹ win7 
		PKTHREAD pCurKthread = (PKTHREAD)((ULONGLONG)(pThreadListEntry)-KTHREAD_TO_THREADLISTENTRY_OFFSET);
		//KTHREAD +0x088 Teb             	      : Ptr32 Void win7
		//���TEB���Ƿ����û��̣߳���������û��߳�,����������һ��
		if (0x00 < (*(ULONG*)((ULONGLONG)pCurKthread + KTHREAD_TO_TEB_OFFSET)) <= 0x80000000)
		{
			KdPrint(("Inject ETHREAD Struct Address:0x%08X",(ULONG)pCurKthread));
			//�������������㣬˵�����û��̣߳����ؼ���
			return (PETHREAD)pCurKthread;
		}
		else
		{
			//���������һ��
			pThreadListEntry = pThreadListEntry->Flink;
		}
	}
	KdPrint(("Not the Process of user Thread!\r\n"));
	//������е�������˵���˽�����û���û��߳�
	return (PETHREAD)0x00;

}

//�����û��ڴ�
PVOID AllocateUserVirtualMemory(PEPROCESS pErpocess)
{
	//��EPROCESSת�ɾ��
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

	//����ShellCode
	RtlCopyMemory((PVOID)pBaseAddr,g_EipShellCode,sizeof(g_EipShellCode));
	//���Dll·��
	//RtlCopyMemory((PVOID)(pBaseAddr + sizeof(g_EipShellCode)),DllPath,uCodeSize - sizeof(g_EipShellCode));
	//�������뵽�ĵ�ַ
	return (PVOID)pBaseAddr;
}