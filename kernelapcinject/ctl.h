#pragma pack(1)
typedef unsigned short WORD;
typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment, //原始的进程环境
	AttachedApcEnvironment, //挂靠后的进程环境
	CurrentApcEnvironment, // 当前环境
	InsertApcEnvironment   //被插入时的环境
} KAPC_ENVIRONMENT;
typedef
VOID
(*PKNORMAL_ROUTINE) (
IN PVOID NormalContext,
IN PVOID SystemArgument1,
IN PVOID SystemArgument2
);
typedef
VOID
(*PKKERNEL_ROUTINE) (
IN struct _KAPC *Apc,
IN OUT PKNORMAL_ROUTINE *NormalRoutine,
IN OUT PVOID *NormalContext,
IN OUT PVOID *SystemArgument1,
IN OUT PVOID *SystemArgument2
);

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
IN struct _KAPC *Apc
);
typedef struct  _MDZZ
{
	BOOLEAN KernelStackResident : 1;
	BOOLEAN ReadyTransition : 1;
	BOOLEAN ProcessReadyQueue : 1;
	BOOLEAN WaitNext : 1;
	BOOLEAN SystemAffinityActive : 1;
	BOOLEAN Alertable : 1;
	BOOLEAN GdiFlushActive : 1;
	BOOLEAN UserStackWalkActive : 1;
	BOOLEAN ApcInterruptRequest : 1;
	BOOLEAN ForceDeferSchedule : 1;
	BOOLEAN QuantumEndMigrate : 1;
	BOOLEAN UmsDirectedSwitchEnable : 1;
	BOOLEAN TimerActive : 1;
	BOOLEAN SystemThread : 1;


}MDZZ,*pmdzz;
typedef struct _RWPM_INFO
{
	void* Address;
	void* Buffer;
	SIZE_T Length;
	SIZE_T Type;//0=read;1=write
	KEVENT Event;
}RWPM_INFO, *PRWPM_INFO;
typedef struct readINT{
	DWORD32 information;
	
}objecint, *Pobjecint;

typedef struct _MDLSHECODE{
PMDL mdl;
KEVENT Event;
PETHREAD ethrd;
}MDLSHECODE, *PMDLSHECODE;

typedef
void
(*shellcode_MDL)(void* NormalContext,
void* SystemArgument1,
void* SystemArgument2);
typedef
void
(*NtQueryInformationThread)(
IN HANDLE               ThreadHandle,

IN THREADINFOCLASS      ThreadInformationClass,

OUT PVOID               ThreadInformation,

IN ULONG                ThreadInformationLength,

OUT PULONG              ReturnLength OPTIONAL);
typedef struct _KTHREAD
{
	DISPATCHER_HEADER Header;
	UINT64 CycleTime;
	ULONG HighCycleTime;
	UINT64 QuantumTarget;
	PVOID InitialStack;
	PVOID StackLimit;
	PVOID KernelStack;
	ULONG ThreadLock;
	union
	{
		KAPC_STATE ApcState;
		UCHAR ApcStateFill[23];
	};
	CHAR Priority;
	WORD NextProcessor;
	WORD DeferredProcessor;
	ULONG ApcQueueLock;
	ULONG ContextSwitches;
	UCHAR State;
	UCHAR NpxState;
	UCHAR WaitIrql;
	CHAR WaitMode;
	LONG WaitStatus;
	union
	{
		PKWAIT_BLOCK WaitBlockList;
		PKGATE GateObject;
	};
	union
	{
		ULONG KernelStackResident : 1;
		ULONG ReadyTransition : 1;
		ULONG ProcessReadyQueue : 1;
		ULONG WaitNext : 1;
		ULONG SystemAffinityActive : 1;
		ULONG Alertable : 1;
		ULONG GdiFlushActive : 1;
		ULONG Reserved : 25;
		LONG MiscFlags;
	};
	UCHAR WaitReason;
	UCHAR SwapBusy;
	UCHAR Alerted[2];
	union
	{
		LIST_ENTRY WaitListEntry;
		SINGLE_LIST_ENTRY SwapListEntry;
	};
	PKQUEUE Queue;
	ULONG WaitTime;
	union
	{
		struct
		{
			SHORT KernelApcDisable;
			SHORT SpecialApcDisable;
		};
		ULONG CombinedApcDisable;
	};
	PVOID Teb;
	union
	{
		KTIMER Timer;
		UCHAR TimerFill[40];
	};
	union
	{
		ULONG AutoAlignment : 1;
		ULONG DisableBoost : 1;
		ULONG EtwStackTraceApc1Inserted : 1;
		ULONG EtwStackTraceApc2Inserted : 1;
		ULONG CycleChargePending : 1;
		ULONG CalloutActive : 1;
		ULONG ApcQueueable : 1;
		ULONG EnableStackSwap : 1;
		ULONG GuiThread : 1;
		ULONG ReservedFlags : 23;
		LONG ThreadFlags;
	};
	union
	{
		KWAIT_BLOCK WaitBlock[4];
		struct
		{
			UCHAR WaitBlockFill0[23];
			UCHAR IdealProcessor;
		};
		struct
		{
			UCHAR WaitBlockFill1[47];
			CHAR PreviousMode;
		};
		struct
		{
			UCHAR WaitBlockFill2[71];
			UCHAR ResourceIndex;
		};
		UCHAR WaitBlockFill3[95];
	};
	UCHAR LargeStack;
	LIST_ENTRY QueueListEntry;
	PKTRAP_FRAME TrapFrame;
	PVOID FirstArgument;
	union
	{
		PVOID CallbackStack;
		ULONG CallbackDepth;
	};
	PVOID ServiceTable;
	UCHAR ApcStateIndex;
	CHAR BasePriority;
	CHAR PriorityDecrement;
	UCHAR Preempted;
	UCHAR AdjustReason;
	CHAR AdjustIncrement;
	UCHAR Spare01;
	CHAR Saturation;
	ULONG SystemCallNumber;
	ULONG Spare02;
	ULONG UserAffinity;
	PKPROCESS Process;
	ULONG Affinity;
	PKAPC_STATE ApcStatePointer[2];
	union
	{
		KAPC_STATE SavedApcState;
		UCHAR SavedApcStateFill[23];
	};
	CHAR FreezeCount;
	CHAR SuspendCount;
	UCHAR UserIdealProcessor;
	UCHAR Spare03;
	UCHAR Iopl;
	PVOID Win32Thread;
	PVOID StackBase;
	union
	{
		KAPC SuspendApc;
		struct
		{
			UCHAR SuspendApcFill0[1];
			CHAR Spare04;
		};
		struct
		{
			UCHAR SuspendApcFill1[3];
			UCHAR QuantumReset;
		};
		struct
		{
			UCHAR SuspendApcFill2[4];
			ULONG KernelTime;
		};
		struct
		{
			UCHAR SuspendApcFill3[36];
			//PKPRCB WaitPrcb;
		};
		struct
		{
			UCHAR SuspendApcFill4[40];
			PVOID LegoData;
		};
		UCHAR SuspendApcFill5[47];
	};
	UCHAR PowerState;
	ULONG UserTime;
	union
	{
		KSEMAPHORE SuspendSemaphore;
		UCHAR SuspendSemaphorefill[20];
	};
	ULONG SListFaultCount;
	LIST_ENTRY ThreadListEntry;
	LIST_ENTRY MutantListHead;
	PVOID SListFaultAddress;
	PVOID MdlForLockedTeb;
} KTHREAD, *PKTHREAD_shao;

typedef struct _SYSTEM_SERVICE_TABLE{
	PVOID       ServiceTableBase;
	PVOID       ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID       ParamTableBase;

} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

//_SERVICE_DESCRIPTOR_TABLE结构声明  
typedef struct _SERVICE_DESCRIPTOR_TABLE{
	SYSTEM_SERVICE_TABLE ntoskrnl;  // ntoskrnl.exe (native api)  
	SYSTEM_SERVICE_TABLE win32k;    // win32k.sys   (gdi/user)  
	SYSTEM_SERVICE_TABLE Table3;    // not used  
	SYSTEM_SERVICE_TABLE Table4;    // not used  

}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
ULONGLONG GetFuncAddr(ULONG id);


//系统服务描述符表


typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT pDeviceObject;	//设备指针
	UNICODE_STRING ustrDeviceName;	//设备名
	UNICODE_STRING ustrSymLinkName;	//符号链接名
	ULONG uProcessId;				//进程的PID
	ULONG uInjectCount;				//注入线程的数量
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _CONTEXT_WOW64                   // 25 elements, 0x2CC bytes (sizeof) 
{
	/*0x000*/     ULONG32      ContextFlags;
	/*0x004*/     ULONG32      Dr0;
	/*0x008*/     ULONG32      Dr1;
	/*0x00C*/     ULONG32      Dr2;
	/*0x010*/     ULONG32      Dr3;
	/*0x014*/     ULONG32      Dr6;
	/*0x018*/     ULONG32      Dr7;
	/*0x01C*/     UCHAR        FloatSave[70]; // 9 elements, 0x70 bytes (sizeof)   
	/*0x08C*/     ULONG32      SegGs;
	/*0x090*/     ULONG32      SegFs;
	/*0x094*/     ULONG32      SegEs;
	/*0x098*/     ULONG32      SegDs;
	/*0x09C*/     ULONG32      Edi;
	/*0x0A0*/     ULONG32      Esi;
	/*0x0A4*/     ULONG32      Ebx;
	/*0x0A8*/     ULONG32      Edx;
	/*0x0AC*/     ULONG32      Ecx;
	/*0x0B0*/     ULONG32      Eax;
	/*0x0B4*/     ULONG32      Ebp;
	/*0x0B8*/     ULONG32      Eip;
	/*0x0BC*/     ULONG32      SegCs;
	/*0x0C0*/     ULONG32      EFlags;
	/*0x0C4*/     ULONG32      Esp;
	/*0x0C8*/     ULONG32      SegSs;
	/*0x0CC*/     UINT8        ExtendedRegisters[512];

}CONTEXT_WOW64, *PCONTEXT_WOW64;


//恢复线程
typedef NTSTATUS(FASTCALL* PSSUSPENDTHREAD)(IN PETHREAD Thread, __out_opt PULONG PreviousSuspendCount);

//暂停线程
typedef ULONG(FASTCALL* KERESUMETHREAD) (__inout PKTHREAD Thread);

//获取线程上下文
typedef NTSTATUS(FASTCALL* PSGETCONTEXTTHREAD)(__in PETHREAD Thread, __inout PCONTEXT_WOW64 ThreadContext, __in KPROCESSOR_MODE Mode);

//设置线程上下文
typedef NTSTATUS(FASTCALL* PSSETCONTEXTTHREAD)(__in PETHREAD Thread, __in PCONTEXT_WOW64 ThreadContext, __in KPROCESSOR_MODE Mode);

typedef struct _WOW64_CONTEXT{
	ULONG Unk1;          //+0x0
	CONTEXT_WOW64 context;       //+0x4
}WOW64_CONTEXT, *PWOW64_CONTEXT;

//注入代码
//NTSTATUS StartInject(IN ULONG uProcessId);
//注入的线程
/*VOID InjectThread(HANDLE PID);
//初始化偏移
BOOLEAN InitializeOffset();
//查找指定进程中的用户线程对象
PETHREAD FindEthreadByEProcess(IN ULONG uProcess);
//申请用户内存
PVOID AllocateUserVirtualMemory(PEPROCESS pErpocess);

PETHREAD LookupThread(HANDLE handle);*/

