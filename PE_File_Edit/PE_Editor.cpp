#include "stdafx.h"

long MBXADDR;

#define CODE_LEN 18
#define CODE_RV1 0xD
#define CODE_RV2 0x12

unsigned char CODE[CODE_LEN] = { 0x6A,0x00,0x6A,0x00,0x6A,0x00,0x6A,0x00,0xE8,0x00,0x00,0x00,0x00,0xE9,0x00,0x00,0x00,0x00 };


//返回对齐后的大小，real实际大小，raw对齐大小参数，Size为对齐后大小
long AlignSize(int Real, int Raw)
{
	long Size = (Real % Raw == 0 ? Real : Real / Raw*Raw + Real%Raw*Raw);
	return Size;
}

/////代码节添加代码///////

//读文件到FileBuffer
unsigned char* FileBuffer(const char* FileName, const char* Mode, long* pSize)
{
	unsigned char* Heap = NULL;
	errno_t Err;	//错误信息
	FILE* Stream;	//文件
	long Size = 0L;

	//打开文件
	Err = fopen_s(&Stream, FileName, Mode);

	if (Err != 0)
	{
		//如果读取文件错误
		if (DEBUG)
			perror("Open file error:");
		printf("Open %s as %s mode error!\n", FileName, Mode);
		return NULL;
	}

	//读取文件大小
	fseek(Stream, 0L, SEEK_END);
	Size = ftell(Stream);
	*pSize = Size;
	fseek(Stream, 0L, SEEK_SET);

	//写入到FileBuffer
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

//提取Code
void GetPECode() {

}

//在FileBuffer里面操作节:添加代码到第一个节
int InsertCodeToPEText(unsigned char* Buffer, unsigned char* Code, int CodeSize)
{
	//判断是不是PE文件，MZ标志和PE标志
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeader32;
	PIMAGE_NT_HEADERS64 pNtHeader64;
	PIMAGE_SECTION_HEADER pSectionHeader;

	//获取pDosHeader
	pDosHeader = (PIMAGE_DOS_HEADER)Buffer;

	//检测MZ标志
	if (pDosHeader->e_magic != 0x5A4D)
	{
		perror("Not PE format file !\n");
		return -1;
	}

	//获取NTHeader，默认32位
	pNtHeader32 = (PIMAGE_NT_HEADERS32)(Buffer + pDosHeader->e_lfanew);
	if (pNtHeader32->Signature != 0x4550)
	{
		perror("PE File format fail!\n");
		return -1;
	}
	if (pNtHeader32->FileHeader.SizeOfOptionalHeader != 0xE0)
	{
		//如果是64位，返回？
		pNtHeader64 = (PIMAGE_NT_HEADERS64)pNtHeader32;
		perror("PE is 64Bit!\n");
		return 1;
	}

	//第一个节的文件对齐空间够不够放18个字节
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
	//第一个节的最后位置的内存偏移地址和文件偏移地址的差，用来计算E8 E9 和OEP的位置，要用到的PE有 OP_Header->OEP,Section_h->praw/va sraw/viualsize
	long Distance = pSectionHeader->VirtualAddress - pSectionHeader->PointerToRawData;  //IMAGEBUFFER和FILEBUFFER的距离

	long InsertAV = pNtHeader32->OptionalHeader.ImageBase + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;                                            //添加代码的VA位置

	long OldOEP = pNtHeader32->OptionalHeader.ImageBase + pNtHeader32->OptionalHeader.AddressOfEntryPoint;  //原文件的OEP+ImageBase



	long* JMP = (long*)(CodeA + 14);
	long* CALL = (long*)(CodeA + 9);
	*CALL = MBXADDR - InsertAV - CODE_RV1;                                         //CALL MessageBoxW 的X位置

	*JMP = OldOEP - InsertAV - CODE_RV2;                                           //JMP回OEP的X位置
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


//将FileBuffer保存到新文件
int SaveBuffer(unsigned char* Buffer, long Size, const char* NewFileN) // 字节为长度单位
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

PIMAGE_SECTION_HEADER   AddSection(_Inout_ LPBYTE& lpFile, // 通过ReadFile()获得的文件在内存指针
	_Inout_ DWORD& dwSize, // 通过GetFileSize()获得的文件大小
	const  TCHAR* pszName, // 新增区段名
	DWORD    dwNameLen, // 新增区段名长度
	DWORD    dwSecSize // 新增区段字节数
)
{

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	// 获取nt头
	// 获取扩展nt头
	PIMAGE_FILE_HEADER      pFileNt = &(NTHEADER(lpFile))->FileHeader;
	PIMAGE_OPTIONAL_HEADER  pOptNt = NTOPTIONALHEADER(lpFile);
	// 获取对齐后的区段描述表对齐后的总大小
	DWORD   dwAligentSectionSize = pOptNt->SizeOfHeaders;
	// 得到所有区段描述表的实际占用字节数
	DWORD   dwLengthOfAllSection = pFileNt->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	// 判断是否有空间容纳新的区段描述表
	if ((dwLengthOfAllSection + sizeof(IMAGE_SECTION_HEADER) <= dwAligentSectionSize))
	{
		// 1. 修改PE标准文件头的Numberofsection +1
		// 2. 修改PE扩展头的SizeofImage 增加一个内存对齐粒度
		// 3. 找打最后一个区段描述表
		//      3.1 修改Misc.Virtualaddress 为一个内存对齐粒度
		//      3.2 修改SizeOfRawData 0x200(实际大小文件对齐后的大小)
		//      3.3 修改PointerToRawData 为上一个PointerToRawData+Pointer +SizeOfRawData的位置
		//      3.3 修改VirtualAddress 为上一个VirtualAddress+SizeOfRawData 内存对齐后的位置
		// 有空间
		//在最后一个全段描述表末尾添加一个新的区段描述表
		PIMAGE_SECTION_HEADER   pNewSection = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[pFileNt->NumberOfSections]);
		/// 修改新的区段的读数
		// 修改区段名
		WideCharToMultiByte(CP_ACP, 0,
			pszName, dwNameLen,
			(char*)pNewSection->Name, dwNameLen,
			NULL, NULL);
		pNewSection->Name[dwNameLen] = 0;
		// 修改大小
		pNewSection->Misc.VirtualSize = size2AligentSize(dwSecSize, pOptNt->SectionAlignment);
		// 修改区段文件对齐后文件大小
		pNewSection->SizeOfRawData = size2AligentSize(dwSecSize, pOptNt->FileAlignment);
		// 修改区段的位置
		PIMAGE_SECTION_HEADER pOldSec = &(IMAGE_FIRST_SECTION(NTHEADER(lpFile))[pFileNt->NumberOfSections - 1]);
		pNewSection->PointerToRawData = pOldSec->PointerToRawData + pOldSec->SizeOfRawData;
		// 修改区段的RVA
		pNewSection->VirtualAddress = size2AligentSize(pOldSec->VirtualAddress + pOldSec->SizeOfRawData, pOptNt->SectionAlignment);

		// 增加一个区段描述表计数
		++pFileNt->NumberOfSections;
		// 增加映像大小为新增区段大小内存对齐后的大小
		pOptNt->SizeOfImage += size2AligentSize(dwSecSize, pOptNt->SectionAlignment);
		/// 申请空间追加新增的区段
		DWORD   dwSecAligSize = size2AligentSize(dwSecSize, pOptNt->FileAlignment);
		LPBYTE lpNewFile = new BYTE[dwSize + dwSecAligSize];
		//memset(lpNewFile,0,dwSize + dwSecAligSize);
		// 将原有内容拷贝回去
		memcpy_s(lpNewFile, dwSize + dwSecAligSize, lpFile, dwSize);
		memset(lpNewFile + dwSize, 0, dwSecAligSize); // 以0填充
		delete[]    lpFile;
		lpFile = lpNewFile;
		dwSize += dwSecSize;
		return pNewSection;

	}
	return  NULL;
}