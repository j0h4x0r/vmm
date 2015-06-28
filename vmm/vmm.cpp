#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <conio.h>
#include "vmm.h"

/* 页表 */
PageTableItem pageTable1[PAGE_SUM];
PageTableItem pageTable2[PAGE_SUM];
/* 快表 */
QuickTable quick[QUICK_SUM];
/* 实存空间 */
BYTE actMem[ACTUAL_MEMORY_SIZE];
/* 用文件模拟辅存空间 */
FILE *ptr_auxMem1;
FILE *ptr_auxMem2;
/* 物理块使用标识 */
bool blockStatus[BLOCK_SUM];
/* 访存请求 */
Ptr_MemoryAccessRequest ptr_memAccReq;

unsigned long TIME = 0;
int tag = 1;

HANDLE hMapFile;
LPCVOID pReq;

/* 初始化环境 */
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
		/* 使用随机数设置该页的保护类型 */
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
		/* 设置该页对应的辅存地址 */
		pageTable1[i].auxAddr = i * PAGE_SIZE * 2;
	}
	for (int i = 0; i < PAGE_SUM; i++)
	{
	    pageTable2[i].pageNum = i;
		pageTable2[i].filled = false;
		pageTable2[i].edited = false;
		pageTable2[i].count = 0;
		/* 使用随机数设置该页的保护类型 */
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
		/* 设置该页对应的辅存地址 */
		pageTable2[i].auxAddr = i * PAGE_SIZE * 2;
	}
	for (int j = 0; j < BLOCK_SUM; j++)
	{
		/* 随机选择一些物理块进行页面装入 */
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


/* 响应请求 */
void do_response()
{
	Ptr_PageTableItem ptr_pageTabIt;
	unsigned int pageNum, offAddr;
	unsigned int actAddr;
	int i = 0x80;
	int flag = 0;

	/* 检查地址是否越界 */
	if (ptr_memAccReq->virAddr < 0 || ptr_memAccReq->virAddr >= VIRTUAL_MEMORY_SIZE)
	{
		do_error(ERROR_OVER_BOUNDARY);
		return;
	}

	/* 计算页号和页内偏移值 */
	pageNum = ptr_memAccReq->virAddr / PAGE_SIZE;
	offAddr = ptr_memAccReq->virAddr % PAGE_SIZE;
	printf("页号为：%u\t页内偏移为：%u\n", pageNum, offAddr);

	/*  查快表 */
	for(int i = 0; i < QUICK_SUM; i++){
		if(quick[i].program == ptr_memAccReq->tag && quick[i].pageNum == pageNum && quick[i].feature == 1){
			flag = 1;

			if(ptr_memAccReq->tag == 1)
				pageTable1[pageNum].LRU_count = pageTable1[pageNum].LRU_count >> 1;
			else
				pageTable2[pageNum].LRU_count = i | pageTable2[pageNum].LRU_count;

			actAddr = quick[i].blockNum * PAGE_SIZE + offAddr;

			printf("在快表中\n");
			printf("实地址为：%u\n", actAddr);

			/* 检查页面访问权限并处理访存请求 */
			switch (ptr_memAccReq->reqType)
			{
				case REQUEST_READ: //读请求
				{
					if (!(quick[i].proType & READABLE)) //页面不可读
					{
						do_error(ERROR_READ_DENY);
						quick[i].feature=0;
						return;
					}
					/* 读取实存中的内容 */
					printf("读操作成功，值为：%02X\n", actMem[actAddr]);
					break;
				}
				case REQUEST_WRITE: //写请求
				{
					if (!(quick[i].proType & WRITABLE)) //页面不可写
					{
						do_error(ERROR_WRITE_DENY);
						quick[i].feature=0;
						return;
					}
					/* 向实存中写入请求的内容 */
					actMem[actAddr] = ptr_memAccReq->value;
					ptr_pageTabIt->edited = true;
					printf("写操作成功\n");
					break;
				}
				case REQUEST_EXECUTE: //执行请求
				{
					if (!(quick[i].proType & EXECUTABLE)) //页面不可执行
					{
						do_error(ERROR_EXECUTE_DENY);
						quick[i].feature=0;
						return;
					}
					printf("执行成功\n");
					break;
				}
				default: //非法请求类型
				{
					do_error(ERROR_INVALID_REQUEST);
						quick[i].feature=0;
					return;
				}
			}
			break;
		}
	}

	/* 不在快表中 */
	if(!flag)
	{
		printf("不在快表中\n");
		/* 获取对应页表项 */
		if(ptr_memAccReq->tag == 1)
			ptr_pageTabIt = &pageTable1[pageNum];
		else
			ptr_pageTabIt = &pageTable2[pageNum];

		/* 根据特征位决定是否产生缺页中断 */
		if (!ptr_pageTabIt->filled)
		{
			do_page_fault(ptr_pageTabIt);
		}

		if(ptr_memAccReq->tag == 1)
			pageTable1[pageNum].LRU_count = pageTable1[pageNum].LRU_count >> 1;
		else
			pageTable2[pageNum].LRU_count = i | pageTable2[pageNum].LRU_count;

		actAddr = ptr_pageTabIt->blockNum * PAGE_SIZE + offAddr;
		printf("实地址为：%u\n", actAddr);

		/* 检查页面访问权限并处理访存请求 */
		switch (ptr_memAccReq->reqType)
		{
			case REQUEST_READ: //读请求
			{
				ptr_pageTabIt->count++;
				if (!(ptr_pageTabIt->proType & READABLE)) //页面不可读
				{
					do_error(ERROR_READ_DENY);
					return;
				}
				/* 读取实存中的内容 */
				printf("读操作成功：值为%02X\n", actMem[actAddr]);
				break;
			}
			case REQUEST_WRITE: //写请求
			{
				ptr_pageTabIt->count++;
				if (!(ptr_pageTabIt->proType & WRITABLE)) //页面不可写
				{
					do_error(ERROR_WRITE_DENY);
					return;
				}
				/* 向实存中写入请求的内容 */
				actMem[actAddr] = ptr_memAccReq->value;
				ptr_pageTabIt->edited = true;
				printf("写操作成功\n");
				break;
			}
			case REQUEST_EXECUTE: //执行请求
			{
				ptr_pageTabIt->count++;
				if (!(ptr_pageTabIt->proType & EXECUTABLE)) //页面不可执行
				{
					do_error(ERROR_EXECUTE_DENY);
					return;
				}
				printf("执行成功\n");
				break;
			}
			default: //非法请求类型
			{
				do_error(ERROR_INVALID_REQUEST);
				return;
			}
		}
	}
}

/* 处理缺页中断 */
void do_page_fault(Ptr_PageTableItem ptr_pageTabIt)
{
	printf("产生缺页中断，开始进行调页...\n");
	for (unsigned int i = 0; i < BLOCK_SUM; i++)
	{
		if (!blockStatus[i])
		{
			/* 读辅存内容，写入到实存 */
			do_page_in(ptr_pageTabIt, i);

			/* 更新页表内容 */
			ptr_pageTabIt->blockNum = i;
			ptr_pageTabIt->filled = true;
			ptr_pageTabIt->edited = false;
			ptr_pageTabIt->count = 0;

			blockStatus[i] = true;
			return;
		}
	}
	/* 没有空闲物理块，进行页面替换 */
	//do_LFU(ptr_pageTabIt);
	do_LRU(ptr_pageTabIt);
}

/* 根据LFU算法进行页面替换 */
void do_LFU(Ptr_PageTableItem ptr_pageTabIt)
{
	printf("没有空闲物理块，开始进行LFU页面替换...\n");
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
	printf("选择程序%d第%u页进行替换\n", ptr_memAccReq->tag, page);
	if(ptr_memAccReq->tag == 1)
	{
		if (pageTable1[page].edited)
		{
			/* 页面内容有修改，需要写回至辅存 */
			printf("该页内容有修改，写回至辅存\n");
			do_page_out(&pageTable1[page]);
		}
		pageTable1[page].filled = false;
		pageTable1[page].count = 0;
		/* 读辅存内容，写入到实存 */
		do_page_in(ptr_pageTabIt, pageTable1[page].blockNum);
	}
	else
	{
		if (pageTable2[page].edited)
		{
			/* 页面内容有修改，需要写回至辅存 */
			printf("该页内容有修改，写回至辅存\n");
			do_page_out(&pageTable2[page]);
		}
		pageTable2[page].filled = false;
		pageTable2[page].count = 0;
		/* 读辅存内容，写入到实存 */
		do_page_in(ptr_pageTabIt, pageTable2[page].blockNum);
	}

	/* 更新页表内容 */
	if(ptr_memAccReq->tag == 1)
		ptr_pageTabIt->blockNum = pageTable1[page].blockNum;
	else
		ptr_pageTabIt->blockNum = pageTable2[page].blockNum;
	ptr_pageTabIt->filled = true;
	ptr_pageTabIt->edited = false;
	ptr_pageTabIt->count = 0;
	printf("页面替换成功\n");
}

void do_LRU(Ptr_PageTableItem ptr_pageTabIt)
{
    unsigned int i, min, page;
    printf("没有空闲物理块，开始进行LRU页面替换...\n");
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
	printf("选择程序%d第%u页进行替换\n", ptr_memAccReq->tag, page);

	if(ptr_memAccReq->tag == 1)
	{
		if (pageTable1[page].edited)
		{
			/* 页面内容有修改，需要写回至辅存 */
			printf("该页内容有修改，写回至辅存\n");
			do_page_out(&pageTable1[page]);
		}
		pageTable1[page].filled = FALSE;
		pageTable1[page].count = 0;
		pageTable1[page].LRU_count = 0;
		/* 读辅存内容，写入到实存 */
		do_page_in(ptr_pageTabIt, pageTable1[page].blockNum);
	}
	else
	{
		if (pageTable2[page].edited)
		{
			/* 页面内容有修改，需要写回至辅存 */
			printf("该页内容有修改，写回至辅存\n");
			do_page_out(&pageTable2[page]);
		}
		pageTable2[page].filled = FALSE;
		pageTable2[page].count = 0;
		pageTable2[page].LRU_count = 0;
		/* 读辅存内容，写入到实存 */
		do_page_in(ptr_pageTabIt, pageTable2[page].blockNum);
	}

	/* 更新页表内容 */
	if(ptr_memAccReq->tag == 1)
		ptr_pageTabIt->blockNum = pageTable1[page].blockNum;
	else
		ptr_pageTabIt->blockNum = pageTable2[page].blockNum;

	ptr_pageTabIt->filled = TRUE;
	ptr_pageTabIt->edited = FALSE;
	ptr_pageTabIt->count = 0;
	ptr_pageTabIt->LRU_count = 0;
	printf("页面替换成功\n");
}

/* 将辅存内容写入实存 */
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
		/* 查找未被访问过的 */
		if(quick[i].feature==0){
			temp = i;
			flag = 1;
		}
	}
	/* 如果全都被访问过 */
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

	printf("调页成功：辅存地址%u-->>物理块%u\n", ptr_pageTabIt->auxAddr, blockNum);
}

/* 将被替换页面的内容写回辅存 */
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
	printf("写回成功：物理块%u-->>辅存地址%u\n", ptr_pageTabIt->auxAddr, ptr_pageTabIt->blockNum);
}

/* 错误处理 */
void do_error(ERROR_CODE code)
{
	switch (code)
	{
		case ERROR_READ_DENY:
		{
			printf("访存失败：该地址内容不可读\n");
			break;
		}
		case ERROR_WRITE_DENY:
		{
			printf("访存失败：该地址内容不可写\n");
			break;
		}
		case ERROR_EXECUTE_DENY:
		{
			printf("访存失败：该地址内容不可执行\n");
			break;
		}
		case ERROR_INVALID_REQUEST:
		{
			printf("访存失败：非法访存请求\n");
			break;
		}
		case ERROR_OVER_BOUNDARY:
		{
			printf("访存失败：地址越界\n");
			break;
		}
		case ERROR_FILE_OPEN_FAILED:
		{
			printf("系统错误：打开文件失败\n");
			break;
		}
		case ERROR_FILE_CLOSE_FAILED:
		{
			printf("系统错误：关闭文件失败\n");
			break;
		}
		case ERROR_FILE_SEEK_FAILED:
		{
			printf("系统错误：文件指针定位失败\n");
			break;
		}
		case ERROR_FILE_READ_FAILED:
		{
			printf("系统错误：读取文件失败\n");
			break;
		}
		case ERROR_FILE_WRITE_FAILED:
		{
			printf("系统错误：写入文件失败\n");
			break;
		}
		default:
		{
			printf("未知错误：没有这个错误代码\n");
		}
	}
}

/* 打印页表 */
void do_print_info()
{
	char str[4];
	printf("程序1：\n");
	printf("页号\t块号\t装入\t修改\t保护\t计数\t辅存\n");
	for (unsigned int i = 0; i < PAGE_SUM; i++)
	{
		printf("%u\t%u\t%u\t%u\t%s\t%u\t%u\n", i, pageTable1[i].blockNum, pageTable1[i].filled,
			pageTable1[i].edited, get_proType_str(str, pageTable1[i].proType),
			pageTable1[i].count, pageTable1[i].auxAddr);
	}
	printf("程序2：\n");
	printf("页号\t块号\t装入\t修改\t保护\t计数\t辅存\n");
	for (unsigned int i = 0; i < PAGE_SUM; i++)
	{
		printf("%u\t%u\t%u\t%u\t%s\t%u\t%u\n", i, pageTable2[i].blockNum, pageTable2[i].filled,
			pageTable2[i].edited, get_proType_str(str, pageTable2[i].proType),
			pageTable2[i].count, pageTable2[i].auxAddr);
	}
}

/* 打印快表 */
void do_print_quick(){
	char str[4];
	printf("快表号\t程序\t页号\t块号\t保护\t访问\t特征\t时间\n");
	for(int i = 0; i < QUICK_SUM; i++){
		printf("%u\t%u\t%u\t%u\t%s\t%u\t%u\n", i, quick[i].program, quick[i].pageNum,
			quick[i].blockNum, get_proType_str(str, quick[i].proType), quick[i].feature, quick[i].time);
	}
}

/* 获取页面保护类型字符串 */
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
	/* 在循环中模拟访存请求与处理过程 */
	while (!kbhit())
	{
		memcpy(ptr_memAccReq, pReq, sizeof(MemoryAccessRequest));
		do_response();
		do_print_info();
		do_print_quick();
		/* 随机休眠5～10秒 */
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
