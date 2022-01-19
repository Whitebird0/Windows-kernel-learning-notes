#include<ntifs.h>

PDRIVER_OBJECT g_DriverObject = NULL;
CHAR szCodeFlag1[] = { 0xB1 ,0x1B ,0x88 ,0x45 ,0x0B };
CHAR szCodeFlag2[] = { 0x8B,0xCE,0xF0 ,0x0F,0xBA,0x29,0x1F };
typedef VOID(*FunMiProcessLoaderEntry)(ULONG ulEntry, LOGICAL lflag);


NTSTATUS FindMiProcessLoaderEntryAddr(ULONG ulStartAddress, ULONG ulEndAddress, ULONG* retFunAddress) {

	for (size_t i = ulStartAddress; i < ulEndAddress; i++)
	{
		if (memcmp(ulStartAddress, szCodeFlag1, sizeof(szCodeFlag1)) == 0) {
			if (memcmp(((char*)ulStartAddress + 0x23), szCodeFlag2, sizeof(szCodeFlag2)) == 0)
			{
				*retFunAddress = ulStartAddress;
				return STATUS_SUCCESS;
			}
		}
		(char*)ulStartAddress++;
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

NTSTATUS EnmuThreadFunc(DWORD_PTR pEprocess,ULONG ThreadId) {
	ULONG ulNtosAddr;
	ULONG ulFunAddr;
	ULONG ulNtosStartAddr;
	ULONG ulNtosEndAddr;
	PLIST_ENTRY	HeadNode = NULL;
	PLIST_ENTRY NextNode = NULL;
	FunMiProcessLoaderEntry MyMiProcessLoaderEntry;
	SearchNtosKenlAddr(g_DriverObject, &ulNtosAddr);
	ulNtosStartAddr = *(ULONG*)(ulNtosAddr + 0x18);
	ulNtosEndAddr = *(ULONG*)(ulNtosAddr + 0x20) + ulNtosStartAddr;
	FindMiProcessLoaderEntryAddr(ulNtosStartAddr, ulNtosEndAddr, &ulFunAddr);
	ulFunAddr = ulFunAddr - 0x1E;
	MyMiProcessLoaderEntry = ulFunAddr;
	HeadNode = (PLIST_ENTRY)(pEprocess + 0x188); 
	NextNode = HeadNode->Flink; 
	while (NextNode!= HeadNode)
	{
		PETHREAD pEhread = (PETHREAD)((ULONG)NextNode - 0X268);
		PCLIENT_ID pCid = (PCLIENT_ID)((ULONG)pEhread + 0x22c);
		if (pCid->UniqueThread== ThreadId)
		{
			MyMiProcessLoaderEntry(NextNode, FALSE);
		}
		DbgPrint("Thread Id=%d", pCid->UniqueThread);
		DbgPrint("ETHREAD =0x%X", pEhread);
		NextNode = NextNode->Flink;
	}
	
}


NTSTATUS EnmuProcessFunc(ULONG  ulPID, ULONG ThreadId) {
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
			EnmuThreadFunc(pEprocess,ThreadId);
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
	EnmuProcessFunc(3572,2064);//自己填写进程与线程ID
	return STATUS_SUCCESS;

}
