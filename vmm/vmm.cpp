#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <conio.h>
#include "vmm.h"

/* ҳ�� */
PageTableItem pageTable1[PAGE_SUM];
PageTableItem pageTable2[PAGE_SUM];
/* ��� */
QuickTable quick[QUICK_SUM];
/* ʵ��ռ� */
BYTE actMem[ACTUAL_MEMORY_SIZE];
/* ���ļ�ģ�⸨��ռ� */
FILE *ptr_auxMem1;
FILE *ptr_auxMem2;
/* �����ʹ�ñ�ʶ */
bool blockStatus[BLOCK_SUM];
/* �ô����� */
Ptr_MemoryAccessRequest ptr_memAccReq;

unsigned long TIME = 0;
int tag = 1;

HANDLE hMapFile;
LPCVOID pReq;

/* ��ʼ������ */
void do_init()
{
	srand((unsigned int) time(NULL));
	for(int i = 0; i < QUICK_SUM; i++) {
		quick[i].blockNum = 0;
		quick[i].pageNum = 0;
		quick[i].program = 0;
		quick[i].time = 0;
		quick[i].feature = 0;
	}
	for (int i = 0; i < PAGE_SUM; i++)
	{
	    pageTable1[i].pageNum = i;
		pageTable1[i].filled = false;
		pageTable1[i].edited = false;
		pageTable1[i].count = 0;
		/* ʹ����������ø�ҳ�ı������� */
		switch (rand() % 7)
		{
			case 0:
			{
				pageTable1[i].proType = READABLE;
				break;
			}
			case 1:
			{
				pageTable1[i].proType = WRITABLE;
				break;
			}
			case 2:
			{
				pageTable1[i].proType = EXECUTABLE;
				break;
			}
			case 3:
			{
				pageTable1[i].proType = READABLE | WRITABLE;
				break;
			}
			case 4:
			{
				pageTable1[i].proType = READABLE | EXECUTABLE;
				break;
			}
			case 5:
			{
				pageTable1[i].proType = WRITABLE | EXECUTABLE;
				break;
			}
			case 6:
			{
				pageTable1[i].proType = READABLE | WRITABLE | EXECUTABLE;
				break;
			}
			default:
				break;
		}
		/* ���ø�ҳ��Ӧ�ĸ����ַ */
		pageTable1[i].auxAddr = i * PAGE_SIZE * 2;
	}
	for (int i = 0; i < PAGE_SUM; i++)
	{
	    pageTable2[i].pageNum = i;
		pageTable2[i].filled = false;
		pageTable2[i].edited = false;
		pageTable2[i].count = 0;
		/* ʹ����������ø�ҳ�ı������� */
		switch (rand() % 7)
		{
			case 0:
			{
				pageTable2[i].proType = READABLE;
				break;
			}
			case 1:
			{
				pageTable2[i].proType = WRITABLE;
				break;
			}
			case 2:
			{
				pageTable2[i].proType = EXECUTABLE;
				break;
			}
			case 3:
			{
				pageTable2[i].proType = READABLE | WRITABLE;
				break;
			}
			case 4:
			{
				pageTable2[i].proType = READABLE | EXECUTABLE;
				break;
			}
			case 5:
			{
				pageTable2[i].proType = WRITABLE | EXECUTABLE;
				break;
			}
			case 6:
			{
				pageTable2[i].proType = READABLE | WRITABLE | EXECUTABLE;
				break;
			}
			default:
				break;
		}
		/* ���ø�ҳ��Ӧ�ĸ����ַ */
		pageTable2[i].auxAddr = i * PAGE_SIZE * 2;
	}
	for (int j = 0; j < BLOCK_SUM; j++)
	{
		/* ���ѡ��һЩ��������ҳ��װ�� */
		if (rand() % 3 == 0)
		{
			if(rand() % 2 == 0)
			{
			    tag = 1;
				do_page_in(&pageTable1[j], j);
				pageTable1[j].blockNum = j;
				pageTable1[j].filled = true;
				blockStatus[j] = true;
			}
			else
			{
			    tag = 2;
				do_page_in(&pageTable2[j], j);
				pageTable2[j].blockNum = j;
				pageTable2[j].filled = true;
				blockStatus[j] = true;
			}
		}
		else
			blockStatus[j] = false;
	}
}


/* ��Ӧ���� */
void do_response()
{
	Ptr_PageTableItem ptr_pageTabIt;
	unsigned int pageNum, offAddr;
	unsigned int actAddr;
	int i = 0x80;
	int flag = 0;

	/* ����ַ�Ƿ�Խ�� */
	if (ptr_memAccReq->virAddr < 0 || ptr_memAccReq->virAddr >= VIRTUAL_MEMORY_SIZE)
	{
		do_error(ERROR_OVER_BOUNDARY);
		return;
	}

	/* ����ҳ�ź�ҳ��ƫ��ֵ */
	pageNum = ptr_memAccReq->virAddr / PAGE_SIZE;
	offAddr = ptr_memAccReq->virAddr % PAGE_SIZE;
	printf("ҳ��Ϊ��%u\tҳ��ƫ��Ϊ��%u\n", pageNum, offAddr);

	/*  ���� */
	for(int i = 0; i < QUICK_SUM; i++){
		if(quick[i].program == ptr_memAccReq->tag && quick[i].pageNum == pageNum && quick[i].feature == 1){
			flag = 1;

			if(ptr_memAccReq->tag == 1)
				pageTable1[pageNum].LRU_count = pageTable1[pageNum].LRU_count >> 1;
			else
				pageTable2[pageNum].LRU_count = i | pageTable2[pageNum].LRU_count;

			actAddr = quick[i].blockNum * PAGE_SIZE + offAddr;

			printf("�ڿ����\n");
			printf("ʵ��ַΪ��%u\n", actAddr);

			/* ���ҳ�����Ȩ�޲�����ô����� */
			switch (ptr_memAccReq->reqType)
			{
				case REQUEST_READ: //������
				{
					if (!(quick[i].proType & READABLE)) //ҳ�治�ɶ�
					{
						do_error(ERROR_READ_DENY);
						quick[i].feature=0;
						return;
					}
					/* ��ȡʵ���е����� */
					printf("�������ɹ���ֵΪ��%02X\n", actMem[actAddr]);
					break;
				}
				case REQUEST_WRITE: //д����
				{
					if (!(quick[i].proType & WRITABLE)) //ҳ�治��д
					{
						do_error(ERROR_WRITE_DENY);
						quick[i].feature=0;
						return;
					}
					/* ��ʵ����д����������� */
					actMem[actAddr] = ptr_memAccReq->value;
					ptr_pageTabIt->edited = true;
					printf("д�����ɹ�\n");
					break;
				}
				case REQUEST_EXECUTE: //ִ������
				{
					if (!(quick[i].proType & EXECUTABLE)) //ҳ�治��ִ��
					{
						do_error(ERROR_EXECUTE_DENY);
						quick[i].feature=0;
						return;
					}
					printf("ִ�гɹ�\n");
					break;
				}
				default: //�Ƿ���������
				{
					do_error(ERROR_INVALID_REQUEST);
						quick[i].feature=0;
					return;
				}
			}
			break;
		}
	}

	/* ���ڿ���� */
	if(!flag)
	{
		printf("���ڿ����\n");
		/* ��ȡ��Ӧҳ���� */
		if(ptr_memAccReq->tag == 1)
			ptr_pageTabIt = &pageTable1[pageNum];
		else
			ptr_pageTabIt = &pageTable2[pageNum];

		/* ��������λ�����Ƿ����ȱҳ�ж� */
		if (!ptr_pageTabIt->filled)
		{
			do_page_fault(ptr_pageTabIt);
		}

		if(ptr_memAccReq->tag == 1)
			pageTable1[pageNum].LRU_count = pageTable1[pageNum].LRU_count >> 1;
		else
			pageTable2[pageNum].LRU_count = i | pageTable2[pageNum].LRU_count;

		actAddr = ptr_pageTabIt->blockNum * PAGE_SIZE + offAddr;
		printf("ʵ��ַΪ��%u\n", actAddr);

		/* ���ҳ�����Ȩ�޲�����ô����� */
		switch (ptr_memAccReq->reqType)
		{
			case REQUEST_READ: //������
			{
				ptr_pageTabIt->count++;
				if (!(ptr_pageTabIt->proType & READABLE)) //ҳ�治�ɶ�
				{
					do_error(ERROR_READ_DENY);
					return;
				}
				/* ��ȡʵ���е����� */
				printf("�������ɹ���ֵΪ%02X\n", actMem[actAddr]);
				break;
			}
			case REQUEST_WRITE: //д����
			{
				ptr_pageTabIt->count++;
				if (!(ptr_pageTabIt->proType & WRITABLE)) //ҳ�治��д
				{
					do_error(ERROR_WRITE_DENY);
					return;
				}
				/* ��ʵ����д����������� */
				actMem[actAddr] = ptr_memAccReq->value;
				ptr_pageTabIt->edited = true;
				printf("д�����ɹ�\n");
				break;
			}
			case REQUEST_EXECUTE: //ִ������
			{
				ptr_pageTabIt->count++;
				if (!(ptr_pageTabIt->proType & EXECUTABLE)) //ҳ�治��ִ��
				{
					do_error(ERROR_EXECUTE_DENY);
					return;
				}
				printf("ִ�гɹ�\n");
				break;
			}
			default: //�Ƿ���������
			{
				do_error(ERROR_INVALID_REQUEST);
				return;
			}
		}
	}
}

/* ����ȱҳ�ж� */
void do_page_fault(Ptr_PageTableItem ptr_pageTabIt)
{
	printf("����ȱҳ�жϣ���ʼ���е�ҳ...\n");
	for (unsigned int i = 0; i < BLOCK_SUM; i++)
	{
		if (!blockStatus[i])
		{
			/* ���������ݣ�д�뵽ʵ�� */
			do_page_in(ptr_pageTabIt, i);

			/* ����ҳ������ */
			ptr_pageTabIt->blockNum = i;
			ptr_pageTabIt->filled = true;
			ptr_pageTabIt->edited = false;
			ptr_pageTabIt->count = 0;

			blockStatus[i] = true;
			return;
		}
	}
	/* û�п�������飬����ҳ���滻 */
	//do_LFU(ptr_pageTabIt);
	do_LRU(ptr_pageTabIt);
}

/* ����LFU�㷨����ҳ���滻 */
void do_LFU(Ptr_PageTableItem ptr_pageTabIt)
{
	printf("û�п�������飬��ʼ����LFUҳ���滻...\n");
	unsigned int page = 0;
	if(ptr_memAccReq->tag == 1)
	{
		for (unsigned int i = 0, min = 0xFFFFFFFF; i < PAGE_SUM; i++)
		{
			if (pageTable1[i].count < min)
			{
				min = pageTable1[i].count;
				page = i;
			}
		}
	}
	else
	{
		for (unsigned int i = 0, min = 0xFFFFFFFF; i < PAGE_SUM; i++)
		{
			if (pageTable2[i].count < min)
			{
				min = pageTable2[i].count;
				page = i;
			}
		}
	}
	printf("ѡ�����%d��%uҳ�����滻\n", ptr_memAccReq->tag, page);
	if(ptr_memAccReq->tag == 1)
	{
		if (pageTable1[page].edited)
		{
			/* ҳ���������޸ģ���Ҫд�������� */
			printf("��ҳ�������޸ģ�д��������\n");
			do_page_out(&pageTable1[page]);
		}
		pageTable1[page].filled = false;
		pageTable1[page].count = 0;
		/* ���������ݣ�д�뵽ʵ�� */
		do_page_in(ptr_pageTabIt, pageTable1[page].blockNum);
	}
	else
	{
		if (pageTable2[page].edited)
		{
			/* ҳ���������޸ģ���Ҫд�������� */
			printf("��ҳ�������޸ģ�д��������\n");
			do_page_out(&pageTable2[page]);
		}
		pageTable2[page].filled = false;
		pageTable2[page].count = 0;
		/* ���������ݣ�д�뵽ʵ�� */
		do_page_in(ptr_pageTabIt, pageTable2[page].blockNum);
	}

	/* ����ҳ������ */
	if(ptr_memAccReq->tag == 1)
		ptr_pageTabIt->blockNum = pageTable1[page].blockNum;
	else
		ptr_pageTabIt->blockNum = pageTable2[page].blockNum;
	ptr_pageTabIt->filled = true;
	ptr_pageTabIt->edited = false;
	ptr_pageTabIt->count = 0;
	printf("ҳ���滻�ɹ�\n");
}

void do_LRU(Ptr_PageTableItem ptr_pageTabIt)
{
    unsigned int i, min, page;
    printf("û�п�������飬��ʼ����LRUҳ���滻...\n");
	if(ptr_memAccReq->tag == 1)
	{
		for (i = 0, min = 0xFFFFFFFF, page = 0; i < PAGE_SUM; i++)
		{
			if (pageTable1[i].LRU_count < min)
			{
				min = pageTable1[i].LRU_count;
				page = i;
			}
		}
	}
	else
	{
		for (i = 0, min = 0xFFFFFFFF, page = 0; i < PAGE_SUM; i++)
		{
			if (pageTable2[i].LRU_count < min)
			{
				min = pageTable2[i].LRU_count;
				page = i;
			}
		}
	}
	printf("ѡ�����%d��%uҳ�����滻\n", ptr_memAccReq->tag, page);

	if(ptr_memAccReq->tag == 1)
	{
		if (pageTable1[page].edited)
		{
			/* ҳ���������޸ģ���Ҫд�������� */
			printf("��ҳ�������޸ģ�д��������\n");
			do_page_out(&pageTable1[page]);
		}
		pageTable1[page].filled = FALSE;
		pageTable1[page].count = 0;
		pageTable1[page].LRU_count = 0;
		/* ���������ݣ�д�뵽ʵ�� */
		do_page_in(ptr_pageTabIt, pageTable1[page].blockNum);
	}
	else
	{
		if (pageTable2[page].edited)
		{
			/* ҳ���������޸ģ���Ҫд�������� */
			printf("��ҳ�������޸ģ�д��������\n");
			do_page_out(&pageTable2[page]);
		}
		pageTable2[page].filled = FALSE;
		pageTable2[page].count = 0;
		pageTable2[page].LRU_count = 0;
		/* ���������ݣ�д�뵽ʵ�� */
		do_page_in(ptr_pageTabIt, pageTable2[page].blockNum);
	}

	/* ����ҳ������ */
	if(ptr_memAccReq->tag == 1)
		ptr_pageTabIt->blockNum = pageTable1[page].blockNum;
	else
		ptr_pageTabIt->blockNum = pageTable2[page].blockNum;

	ptr_pageTabIt->filled = TRUE;
	ptr_pageTabIt->edited = FALSE;
	ptr_pageTabIt->count = 0;
	ptr_pageTabIt->LRU_count = 0;
	printf("ҳ���滻�ɹ�\n");
}

/* ����������д��ʵ�� */
void do_page_in(Ptr_PageTableItem ptr_pageTabIt, unsigned int blockNum)
{
	unsigned int readNum;

	unsigned int flag = 0;
	unsigned int min = 65536, temp = 0;

    if(ptr_memAccReq)
        tag = ptr_memAccReq->tag;
	if(tag == 1)
	{
		if (fseek(ptr_auxMem1, ptr_pageTabIt->auxAddr, SEEK_SET) < 0)
		{
			exit(1);
		}
		if ((readNum = fread(actMem + blockNum * PAGE_SIZE,
			sizeof(BYTE), PAGE_SIZE, ptr_auxMem1)) < PAGE_SIZE)
		{
			exit(1);
		}
	}
	else
	{
		if (fseek(ptr_auxMem2, ptr_pageTabIt->auxAddr, SEEK_SET) < 0)
		{
			exit(1);
		}
		if ((readNum = fread(actMem + blockNum * PAGE_SIZE,
			sizeof(BYTE), PAGE_SIZE, ptr_auxMem2)) < PAGE_SIZE)
		{
			exit(1);
		}
	}

	for(int i = 0; i < QUICK_SUM; i++){
		/* ����δ�����ʹ��� */
		if(quick[i].feature==0){
			temp = i;
			flag = 1;
		}
	}
	/* ���ȫ�������ʹ� */
	if(!flag){
		for(int i = 0; i < QUICK_SUM; i++){
			if(quick[i].time < min){
				temp = i;
				min = quick[i].time;
			}
		}
	}
	quick[temp].time=TIME++;
	quick[temp].pageNum = ptr_pageTabIt->pageNum;
	quick[temp].blockNum = blockNum;
	quick[temp].program = tag;
	quick[temp].proType=ptr_pageTabIt->proType;
	quick[temp].feature = 1;

	printf("��ҳ�ɹ��������ַ%u-->>�����%u\n", ptr_pageTabIt->auxAddr, blockNum);
}

/* �����滻ҳ�������д�ظ��� */
void do_page_out(Ptr_PageTableItem ptr_pageTabIt)
{
	unsigned int writeNum;
	if(ptr_memAccReq->tag == 1)
    {
        if (fseek(ptr_auxMem1, ptr_pageTabIt->auxAddr, SEEK_SET) < 0)
        {
            exit(1);
        }
        if ((writeNum = fwrite(actMem + ptr_pageTabIt->blockNum * PAGE_SIZE,
            sizeof(BYTE), PAGE_SIZE, ptr_auxMem1)) < PAGE_SIZE)
        {
            do_error(ERROR_FILE_WRITE_FAILED);
            exit(1);
        }
    }
	else
    {
        if (fseek(ptr_auxMem2, ptr_pageTabIt->auxAddr, SEEK_SET) < 0)
        {
            exit(1);
        }
        if ((writeNum = fwrite(actMem + ptr_pageTabIt->blockNum * PAGE_SIZE,
            sizeof(BYTE), PAGE_SIZE, ptr_auxMem2)) < PAGE_SIZE)
        {
            do_error(ERROR_FILE_WRITE_FAILED);
            exit(1);
        }
    }
	printf("д�سɹ��������%u-->>�����ַ%u\n", ptr_pageTabIt->auxAddr, ptr_pageTabIt->blockNum);
}

/* ������ */
void do_error(ERROR_CODE code)
{
	switch (code)
	{
		case ERROR_READ_DENY:
		{
			printf("�ô�ʧ�ܣ��õ�ַ���ݲ��ɶ�\n");
			break;
		}
		case ERROR_WRITE_DENY:
		{
			printf("�ô�ʧ�ܣ��õ�ַ���ݲ���д\n");
			break;
		}
		case ERROR_EXECUTE_DENY:
		{
			printf("�ô�ʧ�ܣ��õ�ַ���ݲ���ִ��\n");
			break;
		}
		case ERROR_INVALID_REQUEST:
		{
			printf("�ô�ʧ�ܣ��Ƿ��ô�����\n");
			break;
		}
		case ERROR_OVER_BOUNDARY:
		{
			printf("�ô�ʧ�ܣ���ַԽ��\n");
			break;
		}
		case ERROR_FILE_OPEN_FAILED:
		{
			printf("ϵͳ���󣺴��ļ�ʧ��\n");
			break;
		}
		case ERROR_FILE_CLOSE_FAILED:
		{
			printf("ϵͳ���󣺹ر��ļ�ʧ��\n");
			break;
		}
		case ERROR_FILE_SEEK_FAILED:
		{
			printf("ϵͳ�����ļ�ָ�붨λʧ��\n");
			break;
		}
		case ERROR_FILE_READ_FAILED:
		{
			printf("ϵͳ���󣺶�ȡ�ļ�ʧ��\n");
			break;
		}
		case ERROR_FILE_WRITE_FAILED:
		{
			printf("ϵͳ����д���ļ�ʧ��\n");
			break;
		}
		default:
		{
			printf("δ֪����û������������\n");
		}
	}
}

/* ��ӡҳ�� */
void do_print_info()
{
	char str[4];
	printf("����1��\n");
	printf("ҳ��\t���\tװ��\t�޸�\t����\t����\t����\n");
	for (unsigned int i = 0; i < PAGE_SUM; i++)
	{
		printf("%u\t%u\t%u\t%u\t%s\t%u\t%u\n", i, pageTable1[i].blockNum, pageTable1[i].filled,
			pageTable1[i].edited, get_proType_str(str, pageTable1[i].proType),
			pageTable1[i].count, pageTable1[i].auxAddr);
	}
	printf("����2��\n");
	printf("ҳ��\t���\tװ��\t�޸�\t����\t����\t����\n");
	for (unsigned int i = 0; i < PAGE_SUM; i++)
	{
		printf("%u\t%u\t%u\t%u\t%s\t%u\t%u\n", i, pageTable2[i].blockNum, pageTable2[i].filled,
			pageTable2[i].edited, get_proType_str(str, pageTable2[i].proType),
			pageTable2[i].count, pageTable2[i].auxAddr);
	}
}

/* ��ӡ��� */
void do_print_quick(){
	char str[4];
	printf("����\t����\tҳ��\t���\t����\t����\t����\tʱ��\n");
	for(int i = 0; i < QUICK_SUM; i++){
		printf("%u\t%u\t%u\t%u\t%s\t%u\t%u\n", i, quick[i].program, quick[i].pageNum,
			quick[i].blockNum, get_proType_str(str, quick[i].proType), quick[i].feature, quick[i].time);
	}
}

/* ��ȡҳ�汣�������ַ��� */
char *get_proType_str(char *str, BYTE type)
{
	if (type & READABLE)
		str[0] = 'r';
	else
		str[0] = '-';
	if (type & WRITABLE)
		str[1] = 'w';
	else
		str[1] = '-';
	if (type & EXECUTABLE)
		str[2] = 'x';
	else
		str[2] = '-';
	str[3] = '\0';
	return str;
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

int main(int argc, char* argv[])
{
	if (!(ptr_auxMem1 = fopen(AUXILIARY_MEMORY1, "r+")))
	{
		do_error(ERROR_FILE_OPEN_FAILED);
		exit(1);
	}
	if (!(ptr_auxMem2 = fopen(AUXILIARY_MEMORY2, "r+")))
	{
		do_error(ERROR_FILE_OPEN_FAILED);
		exit(1);
	}

	do_init();
	init_filemap();
	do_print_info();
	ptr_memAccReq = (Ptr_MemoryAccessRequest) malloc(sizeof(MemoryAccessRequest));
	/* ��ѭ����ģ��ô������봦����� */
	while (!kbhit())
	{
		memcpy(ptr_memAccReq, pReq, sizeof(MemoryAccessRequest));
		do_response();
		do_print_info();
		do_print_quick();
		/* �������5��10�� */
		//Sleep(5000 + (rand() % 5) * 5000);
		Sleep(1000);
	}

    UnmapViewOfFile(pReq);
    CloseHandle(hMapFile);

	if (fclose(ptr_auxMem1) == EOF)
	{
		do_error(ERROR_FILE_CLOSE_FAILED);
		exit(1);
	}
	if (fclose(ptr_auxMem2) == EOF)
	{
		do_error(ERROR_FILE_CLOSE_FAILED);
		exit(1);
	}
	return (0);
}
