#ifndef VMM_H
#define VMM_H


/* ģ�⸨����ļ�·�� */
#define AUXILIARY_MEMORY1 "vmm_auxMem1.txt"
#define AUXILIARY_MEMORY2 "vmm_auxMem2.txt"

/* ҳ���С���ֽڣ�*/
#define PAGE_SIZE 4
/* ���ռ��С���ֽڣ� */
#define VIRTUAL_MEMORY_SIZE (64 * 4)
/* ʵ��ռ��С���ֽڣ� */
#define ACTUAL_MEMORY_SIZE (32 * 4)
/* ���Ĵ�С ���ֽڣ�*/
#define QUICK_SIZE (8 * 4)
/* ����ҳ�� */
#define PAGE_SUM (VIRTUAL_MEMORY_SIZE / PAGE_SIZE)
/* ��������� */
#define BLOCK_SUM (ACTUAL_MEMORY_SIZE / PAGE_SIZE)
/* �������� */
#define QUICK_SUM (QUICK_SIZE / PAGE_SIZE)
/* �������� */
#define QUICK_SUM (QUICK_SIZE / PAGE_SIZE)

/* �ɶ���ʶλ */
#define READABLE 0x01u
/* ��д��ʶλ */
#define WRITABLE 0x02u
/* ��ִ�б�ʶλ */
#define EXECUTABLE 0x04u

#define MAPPING_NAME "Global\\MyFileMappingObject"

/* ҳ���� */
typedef struct
{
    unsigned int pageNum;
	unsigned int blockNum; //������
	BOOL filled; //ҳ��װ������λ
	BYTE proType; //ҳ�汣������
	BOOL edited; //ҳ���޸ı�ʶ
	unsigned long auxAddr; //����ַ
	unsigned long count; //ҳ��ʹ�ü�����

	unsigned char LRU_count;// counter for LRU
} PageTableItem, *Ptr_PageTableItem;

/* �ô��������� */
typedef enum {
	REQUEST_READ,
	REQUEST_WRITE,
	REQUEST_EXECUTE
} MemoryAccessRequestType;

/* �ô����� */
typedef struct
{
	MemoryAccessRequestType reqType; //�ô���������
	unsigned long virAddr; //���ַ
	unsigned int tag;//��������ĳ�����
	BYTE value; //д�����ֵ
} MemoryAccessRequest, *Ptr_MemoryAccessRequest;

/* ��� */
typedef struct
{
	unsigned int program;//��Ӧ�ĳ���
	unsigned int pageNum;//ҳ���ַ
	unsigned int blockNum;//������
	BYTE proType; //ҳ�汣������
	unsigned int feature;//����λ
	unsigned long time; //��¼�����ڴ��ʱ��
} QuickTable;

/* �ô������� */
typedef enum {
	ERROR_READ_DENY, //��ҳ���ɶ�
	ERROR_WRITE_DENY, //��ҳ����д
	ERROR_EXECUTE_DENY, //��ҳ����ִ��
	ERROR_INVALID_REQUEST, //�Ƿ���������
	ERROR_OVER_BOUNDARY, //��ַԽ��
	ERROR_FILE_OPEN_FAILED, //�ļ���ʧ��
	ERROR_FILE_CLOSE_FAILED, //�ļ��ر�ʧ��
	ERROR_FILE_SEEK_FAILED, //�ļ�ָ�붨λʧ��
	ERROR_FILE_READ_FAILED, //�ļ���ȡʧ��
	ERROR_FILE_WRITE_FAILED //�ļ�д��ʧ��
} ERROR_CODE;

/* �����ô����� */
void do_request();

/* ��Ӧ�ô����� */
void do_response();

/* ����ȱҳ�ж� */
void do_page_fault(Ptr_PageTableItem);

/* LFUҳ���滻 */
void do_LFU(Ptr_PageTableItem);

/* LRU page exchange */
void do_LRU(Ptr_PageTableItem);

/* װ��ҳ�� */
void do_page_in(Ptr_PageTableItem, unsigned int);

/* д��ҳ�� */
void do_page_out(Ptr_PageTableItem);

/* ������ */
void do_error(ERROR_CODE);

/* ��ӡҳ�������Ϣ */
void do_print_info();

/* ��ȡҳ�汣�������ַ��� */
char *get_proType_str(char *, BYTE);


#endif
