#include<ntifs.h>

PDRIVER_OBJECT g_DriverObject = NULL;
typedef NTSTATUS(*FunPspTerminateThreadByPointer)(PETHREAD  pEthread, NTSTATUS ExitStatus,BOOLEAN DirectTerminate);//函数声明


NTSTATUS FindPspTerminateThreadByPointerAddr(ULONG ulStartAddress, ULONG ulEndAddress, ULONG* retFunAddress) {
	// 8b55ff8b f8e483ec 8b565351 8d570875
	// 000280be 4007f600 868d2874 00000150
	for (size_t i = ulStartAddress; i < ulEndAddress; i++)
	{
		if ((*(ULONG*)i== 0x8b55ff8b)&& (*(ULONG*)(i+4) == 0xf8e483ec)&& (*(ULONG*)(i + 8) == 0x8b565351)&& (*(ULONG*)(i + 12) == 0x8d570875)&& (*(ULONG*)(i + 16) == 0x000280be)&& (*(ULONG*)(i + 20) == 0x4007f600) && (*(ULONG*)(i + 24) == 0x868d2874)&& (*(ULONG*)(i + 28) == 0x00000150))
		{
			*retFunAddress = (PVOID*)i;
		}
	}
	return -1;
}

NTSTATUS SearchNtosKenlAddr(PDRIVER_OBJECT pDriverObject, ULONG* retNtosAddr) {
	PLIST_ENTRY HeadNode = NULL;
	PLIST_ENTRY NextNode = NULL;
	UNICODE_STRING usKernelFileName;
	PUNICODE_STRING pusTempKernelFileName;
	RtlInitUnicodeString(&usKernelFileName, L"ntoskrnl.exe");
	HeadNode = (PLIST_ENTRY)(pDriverObject->DriverSection);
	NextNode = HeadNode->Flink;
	while (NextNode != HeadNode)
	{
		pusTempKernelFileName = (PUNICODE_STRING)((ULONG)NextNode + 0x2c);
		if (RtlCompareUnicodeString(pusTempKernelFileName, &usKernelFileName, TRUE) == 0)
		{
			*retNtosAddr = (ULONG)NextNode;
			return STATUS_SUCCESS;
		}
		NextNode = NextNode->Flink;
	}
	return -1;
}

NTSTATUS EnmuThreadFunc(DWORD_PTR pEprocess) {
	ULONG ulNtosAddr;
	ULONG ulFunAddr;
	ULONG ulNtosStartAddr;
	ULONG ulNtosEndAddr;
	PLIST_ENTRY	HeadNode = NULL;
	PLIST_ENTRY NextNode = NULL;
	FunPspTerminateThreadByPointer MyPspTerminateThreadByPointer;
	SearchNtosKenlAddr(g_DriverObject, &ulNtosAddr);
	ulNtosStartAddr = *(ULONG*)(ulNtosAddr + 0x18);
	ulNtosEndAddr = *(ULONG*)(ulNtosAddr + 0x20) + ulNtosStartAddr;
	FindPspTerminateThreadByPointerAddr(ulNtosStartAddr, ulNtosEndAddr, &ulFunAddr);
	MyPspTerminateThreadByPointer = ulFunAddr;
	HeadNode = (PLIST_ENTRY)(pEprocess + 0x188); 
	NextNode = HeadNode->Flink; 
	while (NextNode!= HeadNode)
	{
		PETHREAD pEhread = (PETHREAD)((ULONG)NextNode - 0X268);
		MyPspTerminateThreadByPointer(pEhread,0, TRUE);
		NextNode = NextNode->Flink;
	}
}


NTSTATUS EnmuProcessFunc(ULONG  ulPID) {
	DWORD_PTR pEprocess = NULL;
	ULONG ulProcessID = 0;
	pEprocess = (DWORD_PTR)PsGetCurrentProcess();
	PLIST_ENTRY HeadNode = NULL;
	PLIST_ENTRY NextNode = NULL;
	HeadNode = (PLIST_ENTRY)(pEprocess + 0xB8);
	NextNode = HeadNode->Flink;
	while (NextNode!= HeadNode)
	{
		pEprocess = ((DWORD_PTR)NextNode - 0xB8);
		ulProcessID = *((ULONG*)(pEprocess+0xb4));
		if (ulProcessID== ulPID)
		{
			EnmuThreadFunc(pEprocess);
			return STATUS_SUCCESS;
		}
		NextNode = NextNode->Flink;
	}
	return STATUS_SUCCESS;
}
VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
	DbgPrint("Unload Driver Success！");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pRegPath) {
	DbgPrint("Load Driver Success！");
	g_DriverObject = pDriverObject;
	pDriverObject->DriverUnload = DriverUnload;
	EnmuProcessFunc(3300);
	return STATUS_SUCCESS;

}
