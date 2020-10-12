#include <Windows.h>
#define FunNumber 20
struct NtFunction
{
    LPCSTR name;
    PVOID Fun;
};
NtFunction list[FunNumber];
DWORD FunMem = 0;
DWORD Size = 0;
DWORD GetFunSpace()
{

   return (DWORD)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessTokenEx")- (DWORD)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenThreadTokenEx");
}
VOID EnDeFun()
{
    if (!FunMem)
    {
        return;
    }
    for (int i=0;i< Size * FunNumber;i++)
    {
        *(BYTE*)(FunMem + i) = *(BYTE*)(FunMem + i) ^ 0x521314;
    }
}
PVOID ExtNtDllFunciton(LPCSTR funname)
{
    if (!FunMem)
    {
      Size = GetFunSpace();
      FunMem = (DWORD)VirtualAlloc(NULL, Size * FunNumber, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
   
    static DWORD Times = 0;
    for (int i=0;i<20;i++)
    {
        if (lstrcmpA(list[i].name,funname)==0)
        {
            return list[i].Fun;
        }
    }
    PVOID Address=GetProcAddress(GetModuleHandle(L"ntdll.dll"), funname);
    if (Address)
    {
        memcpy((PVOID)(FunMem + Times * Size), Address, Size);
        char* name = (char*)malloc(strlen(funname) + 1);
        memcpy(name, funname, strlen(funname) + 1);
        PVOID Address= (PVOID)(FunMem + Times * Size);
        list[Times].name = name;
        list[Times].Fun = Address;
        Times++;
        return Address;
    }
    return 0;
}
typedef NTSTATUS(NTAPI* PNtReadVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    OUT PVOID               Buffer,
    IN ULONG                NumberOfBytesToRead,
    OUT PULONG              NumberOfBytesReaded OPTIONAL);
int main()
{
    printf("NtReadVirtualMemory %x NtWriteVirtualMemory %x NtReadVirtualMemory %x \n", ExtNtDllFunciton("NtReadVirtualMemory"), ExtNtDllFunciton("NtWriteVirtualMemory"), ExtNtDllFunciton("NtReadVirtualMemory"));
    PNtReadVirtualMemory myReadMemory = (PNtReadVirtualMemory)ExtNtDllFunciton("NtReadVirtualMemory");
    DWORD a = 123456;
    DWORD b = 0;
    myReadMemory(GetCurrentProcess(),&a,&b,4,NULL);
    printf("Shadow NtReadVirtualMemory result %d \n",b);
    EnDeFun();//encrypt the code
    printf("Shadow Native API Encrypted\n");
    EnDeFun();//decrypt the code
    printf("Shadow Native API Decrypted\n");
    system("pause");
}
