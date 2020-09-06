#include "stdafx.h"

long MBXADDR;

#define CODE_LEN 18
#define CODE_RV1 0xD
#define CODE_RV2 0x12

unsigned char CODE[CODE_LEN] = { 0x6A,0x00,0x6A,0x00,0x6A,0x00,0x6A,0x00,0xE8,0x00,0x00,0x00,0x00,0xE9,0x00,0x00,0x00,0x00 };


//���ض����Ĵ�С��realʵ�ʴ�С��raw�����С������SizeΪ������С
long AlignSize(int Real, int Raw)
{
	long Size = (Real % Raw == 0 ? Real : Real / Raw*Raw + Real%Raw*Raw);
	return Size;
}

/////�������Ӵ���///////

//���ļ���FileBuffer
unsigned char* FileBuffer(const char* FileName, const char* Mode, long* pSize)
{
	unsigned char* Heap = NULL;
	errno_t Err;	//������Ϣ
	FILE* Stream;	//�ļ�
	long Size = 0L;

	//���ļ�
	Err = fopen_s(&Stream, FileName, Mode);

	if (Err != 0)
	{
		//�����ȡ�ļ�����
		if (DEBUG)
			perror("Open file error:");
		printf("Open %s as %s mode error!\n", FileName, Mode);
		return NULL;
	}

	//��ȡ�ļ���С
	fseek(Stream, 0L, SEEK_END);
	Size = ftell(Stream);
	*pSize = Size;
	fseek(Stream, 0L, SEEK_SET);

	//д�뵽FileBuffer
	Heap = (unsigned char*)malloc(sizeof(char)*Size);
	if (Heap == NULL)
	{
		if (DEBUG)
			printf("Create FileBuffer Error!\n");
		fclose(Stream);
		return NULL;
	}

	fread(Heap, sizeof(char), Size, Stream);
	fclose(Stream);
	return Heap;
}

//��ȡCode
void GetPECode() {

}

//��FileBuffer���������:��Ӵ��뵽��һ����
int InsertCodeToPEText(unsigned char* Buffer, unsigned char* Code, int CodeSize)
{
	//�ж��ǲ���PE�ļ���MZ��־��PE��־
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeader32;
	PIMAGE_NT_HEADERS64 pNtHeader64;
	PIMAGE_SECTION_HEADER pSectionHeader;

	//��ȡpDosHeader
	pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

	//���MZ��־
	if (pDosHeader->e_magic != 0x5A4D)
	{
		perror("Not PE format file !\n");
		return -1;
	}

	//��ȡNTHeader��Ĭ��32λ
	pNtHeader32 = (PIMAGE_NT_HEADERS32)(Buffer + pDosHeader->e_lfanew);
	if (pNtHeader32->Signature != 0x4550)
	{
		perror("PE File format fail!\n");
		return -1;
	}
	if (pNtHeader32->FileHeader.SizeOfOptionalHeader != 0xE0)
	{
		//�����64λ�����أ�
		pNtHeader64 = (PIMAGE_NT_HEADERS64)pNtHeader32;
		perror("PE is 64Bit!\n");
		return 1;
	}

	//��һ���ڵ��ļ�����ռ乻������18���ֽ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHeader32 + 1);
	int PySize, FAlignSize;
	FAlignSize = pSectionHeader->SizeOfRawData;
	PySize = pSectionHeader->Misc.VirtualSize;
	if (FAlignSize - PySize < CODE_LEN)
	{
		perror("First Section Free Buffer Less!");
		return -1;
	}
	unsigned char CodeA[100];
	int x;
	for (x = 0;x < CodeSize;x++)
	{
		CodeA[x] = Code[x];
	}
	//��һ���ڵ����λ�õ��ڴ�ƫ�Ƶ�ַ���ļ�ƫ�Ƶ�ַ�Ĳ��������E8 E9 ��OEP��λ�ã�Ҫ�õ���PE�� OP_Header->OEP,Section_h->praw/va sraw/viualsize
	long Distance = pSectionHeader->VirtualAddress - pSectionHeader->PointerToRawData;  //IMAGEBUFFER��FILEBUFFER�ľ���

	long InsertAV = pNtHeader32->OptionalHeader.ImageBase + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;                                            //��Ӵ����VAλ��

	long OldOEP = pNtHeader32->OptionalHeader.ImageBase + pNtHeader32->OptionalHeader.AddressOfEntryPoint;  //ԭ�ļ���OEP+ImageBase



	long* JMP = (long*)(CodeA + 14);
	long* CALL = (long*)(CodeA + 9);
	*CALL = MBXADDR - InsertAV - CODE_RV1;                                         //CALL MessageBoxW ��Xλ��

	*JMP = OldOEP - InsertAV - CODE_RV2;                                           //JMP��OEP��Xλ��
																				   /*
																				   for(x=0;x<4;x++)
																				   {
																				   CodeA[9+x]=CALL%0x100;
																				   CALL = CALL/0x100;
																				   CodeA[14+x]=JMP%0x100;
																				   JMP = JMP/0x100;
																				   }
																				   */

	unsigned char*  BuffRA = Buffer + pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize;
	int i;
	for (i = 0; i < CodeSize;i++)
	{
		BuffRA[i] = CodeA[i];
	}

	pNtHeader32->OptionalHeader.AddressOfEntryPoint = InsertAV - pNtHeader32->OptionalHeader.ImageBase;

	printf_s("Success!");
	return 0;
}


//��FileBuffer���浽���ļ�
int SaveBuffer(unsigned char* Buffer, long Size, const char* NewFileN) // �ֽ�Ϊ���ȵ�λ
{
	errno_t Err;
	FILE* Stream;
	Err = fopen_s(&Stream, NewFileN, "wb");
	if (Err != 0)
	{
		if (DEBUG)
			printf("Create New File %s error!\n", NewFileN);
		return -1;
	}

	fwrite(Buffer, sizeof(char), Size, Stream);
	fclose(Stream);

	return 0;
}

int main()
{
	long Size;

	char fileName[64];
	scanf_s("%s", fileName, 64);
	unsigned char* Buff = FileBuffer(fileName, "rb", &Size);

	HINSTANCE hInst = LoadLibrary("User32.DLL");

	MBXADDR = (long)GetProcAddress(hInst, "MessageBoxW");

	if (Buff == NULL)
		return -1;
	InsertCodeToPEText(Buff, CODE, CODE_LEN);
	SaveBuffer(Buff, Size, "output.exe");
	system("pause");
	return 0;
}

PIMAGE_SECTION_HEADER   AddSection(_Inout_ LPBYTE& lpFile, // ͨ��ReadFile()��õ��ļ����ڴ�ָ��
	_Inout_ DWORD& dwSize, // ͨ��GetFileSize()��õ��ļ���С
	const  TCHAR* pszName, // ����������
	DWORD    dwNameLen, // ��������������
	DWORD    dwSecSize // ���������ֽ���
)
{

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	// ��ȡntͷ
	// ��ȡ��չntͷ
	PIMAGE_FILE_HEADER      pFileNt = &(NTHEADER(lpFile))->FileHeader;
	PIMAGE_OPTIONAL_HEADER  pOptNt = NTOPTIONALHEADER(lpFile);
	// ��ȡ����������������������ܴ�С
	DWORD   dwAligentSectionSize = pOptNt->SizeOfHeaders;
	// �õ����������������ʵ��ռ���ֽ���
	DWORD   dwLengthOfAllSection = pFileNt->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	// �ж��Ƿ��пռ������µ�����������
	if ((dwLengthOfAllSection + sizeof(IMAGE_SECTION_HEADER) <= dwAligentSectionSize))
	{
		// 1. �޸�PE��׼�ļ�ͷ��Numberofsection +1
		// 2. �޸�PE��չͷ��SizeofImage ����һ���ڴ��������
		// 3. �Ҵ����һ������������
		//      3.1 �޸�Misc.Virtualaddress Ϊһ���ڴ��������
		//      3.2 �޸�SizeOfRawData 0x200(ʵ�ʴ�С�ļ������Ĵ�С)
		//      3.3 �޸�PointerToRawData Ϊ��һ��PointerToRawData+Pointer +SizeOfRawData��λ��
		//      3.3 �޸�VirtualAddress Ϊ��һ��VirtualAddress+SizeOfRawData �ڴ������λ��
		// �пռ�
		//�����һ��ȫ��������ĩβ���һ���µ�����������
		PIMAGE_SECTION_HEADER   pNewSection = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[pFileNt->NumberOfSections]);
		/// �޸��µ����εĶ���
		// �޸�������
		WideCharToMultiByte(CP_ACP, 0,
			pszName, dwNameLen,
			(char*)pNewSection->Name, dwNameLen,
			NULL, NULL);
		pNewSection->Name[dwNameLen] = 0;
		// �޸Ĵ�С
		pNewSection->Misc.VirtualSize = size2AligentSize(dwSecSize, pOptNt->SectionAlignment);
		// �޸������ļ�������ļ���С
		pNewSection->SizeOfRawData = size2AligentSize(dwSecSize, pOptNt->FileAlignment);
		// �޸����ε�λ��
		PIMAGE_SECTION_HEADER pOldSec = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[pFileNt->NumberOfSections - 1]);
		pNewSection->PointerToRawData = pOldSec->PointerToRawData + pOldSec->SizeOfRawData;
		// �޸����ε�RVA
		pNewSection->VirtualAddress = size2AligentSize(pOldSec->VirtualAddress + pOldSec->SizeOfRawData, pOptNt->SectionAlignment);

		// ����һ���������������
		++pFileNt->NumberOfSections;
		// ����ӳ���СΪ�������δ�С�ڴ�����Ĵ�С
		pOptNt->SizeOfImage += size2AligentSize(dwSecSize, pOptNt->SectionAlignment);
		/// ����ռ�׷������������
		DWORD   dwSecAligSize = size2AligentSize(dwSecSize, pOptNt->FileAlignment);
		LPBYTE lpNewFile = new BYTE[dwSize + dwSecAligSize];
		//memset(lpNewFile,0,dwSize + dwSecAligSize);
		// ��ԭ�����ݿ�����ȥ
		memcpy_s(lpNewFile, dwSize + dwSecAligSize, lpFile, dwSize);
		memset(lpNewFile + dwSize, 0, dwSecAligSize); // ��0���
		delete[]    lpFile;
		lpFile = lpNewFile;
		dwSize += dwSecSize;
		return pNewSection;

	}
	return  NULL;
}