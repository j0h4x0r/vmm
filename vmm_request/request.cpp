#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>
#include "vmm.h"

Ptr_MemoryAccessRequest ptr_memAccReq;

HANDLE hMapFile;
LPCVOID pReq;

// �����ô�����
void do_request()
{
	// ������������ַ
	ptr_memAccReq->virAddr = rand() % VIRTUAL_MEMORY_SIZE;
	// ���ָ������
    ptr_memAccReq->tag = rand() % 2 + 1;
	// ���������������
	switch (rand() % 3)
	{
		case 0: //������
		{
			ptr_memAccReq->reqType = REQUEST_READ;
			printf("��������\n����%u\t��ַ��%u\t���ͣ���ȡ\n", ptr_memAccReq->tag, ptr_memAccReq->virAddr);
			break;
		}
		case 1: //д����
		{
			ptr_memAccReq->reqType = REQUEST_WRITE;
			// ���������д���ֵ
			ptr_memAccReq->value = rand() % 0xFFu;
			printf("��������\n����%u\t��ַ��%u\t���ͣ�д��\tֵ��%02X\n", ptr_memAccReq->tag, ptr_memAccReq->virAddr, ptr_memAccReq->value);
			break;
		}
		case 2:
		{
			ptr_memAccReq->reqType = REQUEST_EXECUTE;
			printf("��������\n����%u\t��ַ��%u\t���ͣ�ִ��\n", ptr_memAccReq->tag, ptr_memAccReq->virAddr);
			break;
		}
		default:
			break;
	}
}

void init_filemap()
{
    hMapFile = CreateFileMapping(
        INVALID_HANDLE_VALUE,    // use paging file
        NULL,                    // default security
        PAGE_READWRITE,          // read/write access
        0,                       // maximum object size (high-order DWORD)
        sizeof(MemoryAccessRequest),   // maximum object size (low-order DWORD)
        MAPPING_NAME);                 // name of mapping object

    if (hMapFile == NULL)
    {
        printf(TEXT("Could not create file mapping object (%d).\n"),
            GetLastError());
        exit(1);
    }
    pReq = (LPTSTR) MapViewOfFile(hMapFile,   // handle to map object
        FILE_MAP_ALL_ACCESS, // read/write permission
        0,
        0,
        sizeof(MemoryAccessRequest));
    if (pReq == NULL)
    {
        printf(TEXT("Could not map view of file (%d).\n"),
            GetLastError());
        CloseHandle(hMapFile);
        exit(1);
    }
}

int main()
{
    ptr_memAccReq = (Ptr_MemoryAccessRequest) malloc(sizeof(MemoryAccessRequest));
    init_filemap();
    while(!kbhit())
    {
        do_request();
        memcpy((void *)pReq, ptr_memAccReq, sizeof(MemoryAccessRequest));
        Sleep(1000);
    }
}
