#include<windows.h>
#include<shlwapi.h>
#include<wchar.h>

DWORD MyZwGetContextThread(
	HANDLE Thread,
	LPCONTEXT lpContext)
{
	memset(lpContext,0,sizeof(CONTEXT));
	return 0;
}

DWORD MyZwSetContextThread(
	HANDLE Thread,
	LPCONTEXT lpContext)
{
	memset(lpContext,0,sizeof(CONTEXT));
	return 0;
}


/*
IAT HOOK:挂钩目标输入表中的函数地址

char *szDLLName	指定函数所在的DLL
char *szName	指定函数名
void *Addr	新函数地址 
*/
DWORD IATHook(
	char *szDLLName,
	char *szName,
	void *Addr)
{
	DWORD Protect;
	HMODULE hMod=LoadLibrary(szDLLName);
	DWORD RealAddr=(DWORD)GetProcAddress(hMod,szName);
	hMod=GetModuleHandle(NULL);

	IMAGE_DOS_HEADER *DosHeader=(PIMAGE_DOS_HEADER)hMod;
	IMAGE_OPTIONAL_HEADER *Opthdr=(PIMAGE_OPTIONAL_HEADER)((DWORD)hMod+DosHeader->e_lfanew+24);	//对应PE偏移

	IMAGE_IMPORT_DESCRIPTOR *pImport=(IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)DosHeader+Opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	if(!pImport)
	{
		return FALSE;
	}

	IMAGE_THUNK_DATA32 *Pthunk=(IMAGE_THUNK_DATA32 *)((DWORD)hMod+pImport->FirstThunk);

	while(Pthunk->ul.Function)
	{
		if(RealAddr==Pthunk->ul.Function)
		{
			VirtualProtect(&Pthunk->ul.FUnction,0x1000,PAGE_READWRITE,&Protect);
			Pthunk->ul.Function=(DWORD)Addr;
			break;
		}
		Pthunk++;
	}
	return TRUE;
}

/*
EAT HOOK:挂钩目标输出表中的函数地址

char *szDLLName	指定函数所在的DLL
char *szFunName	指定待替换的原函数名
DWORD NewFun	指定替换的新函数
*/

BOOL EATHook(
	char *szDLLName,
	char *szFunName,
	DWORD NewFun)
{
	DWORD addr=0;
	DWORD index=0;
	HMODULE hMod=LoadLibrary(szDLLName);
	
	DWOED Protect;
	IMAGE_DOS_HEADER *DosHeader=(PIMAGE_DOS_HEADER)hMod;
	IMAGE_OPTIONAL_HEADER *Opthdr=(PIMAGE_OPTIONAL_HEADER)((DWORD)hMod+DosHeader->e_lfanew+24);

	PIMAGE_EXPORT_DIRECTORY Export=(PIMAGE_EXPORT_DIRECTORY)((BYTE *)DosHeader+Opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions=(ULONG *)((BYTE *)hMod+Export->AddressOfNameOrdinals);

	for(int i=0;i<Export->NumberOfNames;++i)
	{
		index=pAddressOfNameOrdinals[i];
		char *pFuncName=(char *)((BYTE *)hMod+pAddressOfNames[i]);
		if(_strcmp((char *)pFuncName,szFunName)==0)
		{
			addr=pAddressOfFunctions[index];
			break;
		}
	}

	VirtualProtect(&pAddressOfFunctions[index],0x1000,PAGE_READWRITE,&Protect);
	pAddressOfFunctions[index]=(DWORD)NewFun-(DWORD)hMod;
	return TRUE;
}

BOOL WINAPI DllMain(
	HMODULE hModule,
	DWORD dwReason,
	PVOID pvReserved)
{
	if(dwReason==DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		IATHook("kernel32.dll","ExitProcess",MyZwGetContextThread);
	}
	return TRUE;
}


