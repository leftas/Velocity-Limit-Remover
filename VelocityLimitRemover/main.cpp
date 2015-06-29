#include "include.h"
#include <intrin.h>
#include <Winternl.h>
DWORD_PTR g_VelocityLimit, g_VelocityPatch1, g_VelocityPatch2, g_VelocityPatch3, windowsHook, windowsHookProcedure;
void workWithFiles()
{
	g_FileManager.Initialize(".//VelocityLimit.ini");
	if (GetFileAttributes(TEXT(g_FileManager.m_szFileName)) == INVALID_FILE_ATTRIBUTES)
		g_FileManager.WriteFloat("Values", "Limit", 3306.0f);
}
void removeDebuggerCheck()
{
	DWORD64 dwAddr = (DWORD64)GetProcAddress(GetModuleHandleA("KERNELBASE.dll"), "IsDebuggerPresent");
	DWORD dwVirtualProtectBackup;
	bool result = VirtualProtect((BYTE*)dwAddr, 0x20, PAGE_READWRITE, &dwVirtualProtectBackup);
	if (result == NULL)
		Log::Write(Log::Type::FatalError,"Failed to patch debugging.");
	else
	{
		*(BYTE*)(dwAddr) = 0xB8;
		memset((BYTE*)(dwAddr + 0x1), 0x0, 0x4);
		*(BYTE*)(dwAddr + 0x5) = 0xC3;
		VirtualProtect((BYTE*)dwAddr, 0x20, dwVirtualProtectBackup, &dwVirtualProtectBackup);
		Log::Write(Log::Type::Debug, "IsDebuggerPresent patched");
	}
	PPEB peb = (PPEB)__readgsqword(0x60);
	peb->BeingDebugged = false;
	*(DWORD*)((char*)peb + 0xBC) &= ~0x70;
	Log::Write(Log::Type::Normal, "Patched debugger checks.");

}
void removeHook(MODULEINFO baseAddress)
{
	windowsHookProcedure = Pattern::Scan(baseAddress, "48 83 EC 28 33 C9 FF 15 ? ? ? ? 45 33 C9");
	*(DWORD*)windowsHookProcedure = 0xC3;
	Log::Write(Log::Type::Normal, "Patched windows hook");
	/*windowsHook = Pattern::Scan(baseAddress, "48 89 05 ? ? ? ? 48 83 C4 28 E9 ? ? ? ? AC");
	UnhookWindowsHookEx((HHOOK)*(DWORD*)windowsHook);
	Log::Msg("Windows hook unhooked");*/
}



DWORD convertFloatToHex(float value)
{
	return *(DWORD*)&value;
}
float convertHextoFloat(DWORD value)
{
	return *(float*)&value;
}

void WINAPI mainFunction()
{
	Log::Init();
	workWithFiles();
	MODULEINFO baseAddress;	
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &baseAddress, sizeof(MODULEINFO));
	removeHook(baseAddress);
	removeDebuggerCheck();
	Log::Write(Log::Type::Debug, "Base address: %p", baseAddress);
	g_VelocityLimit = Pattern::Scan(baseAddress, "C7 83 ? ? ? ? ? ? ? ? C7 83 ? ? ? ? ? ? ? ? 0F 29 9B ? ? ? ?");
	Log::Write(Log::Type::Debug,"Velocity address: %p", g_VelocityLimit);
	DWORD defaultValue = *(DWORD*)(g_VelocityLimit + 6);
	Log::Write(Log::Type::Debug,"Velocity default limit: in Hex %X  in float:%f ", defaultValue, convertHextoFloat(defaultValue));
	float limit = g_FileManager.ReadFloat("Values", "Limit", 3306.0f);
	*(DWORD*)(g_VelocityLimit + 6) = convertFloatToHex(limit);
	g_VelocityPatch1 = Pattern::Scan(baseAddress, "F3 0F 11 80 ? ? ? ? 48 8B 8F ? ? ? ? 48 8B 41 78 48 8B 90 ? ? ? ? 48 85 D2 74 24");
	Log::Write(Log::Type::Debug, "First velocity patch address: %p", g_VelocityPatch1);
	memset((void*)g_VelocityPatch1, 0x90, 8);
	g_VelocityPatch2 = Pattern::Scan(baseAddress,"F3 0F 11 83 ? ? ? ? 48 8B 07 FF 90 ? ? ? ? F3 0F 11 83 ? ? ? ? 8B 47 10 85 C0 74 14 83 F8 01 74 08 83 C0 FE 83 F8 01 77 07 F3 0F 10 47 ? EB 08 F3 0F 10 05 ? ? ? ? F3 0F 11 83 ? ? ? ?");
	Log::Write(Log::Type::Debug, "Second velocity patch address: %p", g_VelocityPatch2);
	memset((void*)g_VelocityPatch2, 0x90, 8);
	g_VelocityPatch3 = Pattern::Scan(baseAddress, "F3 0F 11 83 ? ? ? ? 48 8B 07 FF 90 ? ? ? ? F3 0F 11 83 ? ? ? ? 8B 47 10 85 C0 74 14 83 F8 01 74 08 83 C0 FE 83 F8 01 77 07 F3 0F 10 47 ? EB 08 F3 0F 10 05 ? ? ? ? 83 7B 08 00");
	Log::Write(Log::Type::Debug,"Third velocity patch address: %p", g_VelocityPatch3);
	memset((void*)g_VelocityPatch3, 0x90, 8);

}
void WINAPI Revert()
{
	if (g_VelocityLimit != NULL)
	{
		*(DWORD*)(g_VelocityLimit + 6) = 0x43160000;
	}
}	

BOOL WINAPI DllMain(HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH){
		DisableThreadLibraryCalls(hinstDLL);
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)mainFunction, NULL, 0, 0);
		return true;
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
		Revert();
		return true;
	}
	return false;
}