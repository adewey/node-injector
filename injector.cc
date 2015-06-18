#include <node.h>
#include <v8.h>
#include <Windows.h>
#include <string>
#include <cstdio>
#include <tlhelp32.h>
#include <psapi.h>

using namespace v8;

void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken); 
}


bool bInjectDll(DWORD dwPid, const char *szDll)
{
	EnableDebugPriv();

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPid);
	if (!hProcess) return false;
	LPVOID lpvLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!lpvLoadLibrary) return false;
	LPVOID lpvMemory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(szDll) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!lpvMemory) return false;
	if (!WriteProcessMemory(hProcess, lpvMemory, (void *)szDll, strlen(szDll) + 1, NULL)) return false;
	if (!CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpvLoadLibrary, lpvMemory, NULL, NULL)) return false;
	CloseHandle(hProcess);
	VirtualFreeEx(hProcess, lpvMemory, 0, MEM_RELEASE);
	return true;
}

bool bIsDllInjected(DWORD dwPid, const char *szDll)
{
	bool res = false;
	MODULEENTRY32 entry;
	entry.dwSize = sizeof(MODULEENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (Module32First(snapshot, &entry))
 		while (Module32Next(snapshot, &entry))
			if (strstr(entry.szModule, szDll)) {
				res = true;
				break;
			}
    return res;
}

DWORD dwGetProcessIdByName(const char *szName)
{
	DWORD res = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry) == TRUE)
        while (Process32Next(snapshot, &entry) == TRUE)
			if (stricmp(entry.szExeFile, szName) == 0) {
				res = entry.th32ProcessID;
				break;
			}
	CloseHandle(snapshot);
    return res;
}

void inject_dll(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    if (args.Length() < 2) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

	DWORD dwPid = (DWORD)args[0]->NumberValue();
	v8::String::Utf8Value arg1_v8(args[1]->ToString());
	std::string arg1_std(*arg1_v8);
	const char *arg1 = arg1_std.c_str();
    
	if (!bInjectDll(dwPid, arg1)) {
		args.GetReturnValue().Set(False(isolate));
        return;
    }
	args.GetReturnValue().Set(True(isolate));
}

void is_dll_injected(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    if (args.Length() < 2) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

	DWORD dwPid = (DWORD)args[0]->NumberValue();
	v8::String::Utf8Value arg1_v8(args[1]->ToString());
	std::string arg1_std(*arg1_v8);
	const char *arg1 = arg1_std.c_str();
    
	if (!bIsDllInjected(dwPid, arg1))
    {
       args.GetReturnValue().Set(False(isolate));
       return;
    }
	args.GetReturnValue().Set(True(isolate));
}

void get_process_id(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    if (args.Length() < 1) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

	v8::String::Utf8Value arg0_v8(args[0]->ToString());
	std::string arg0_std(*arg0_v8);
	const char *arg0 = arg0_std.c_str();

	args.GetReturnValue().Set(Integer::New(isolate, (int)dwGetProcessIdByName(arg0)));
}

void init(Handle<Object> exports)
{
	NODE_SET_METHOD(exports, "inject_dll", inject_dll);
	NODE_SET_METHOD(exports, "is_dll_injected", is_dll_injected);
	NODE_SET_METHOD(exports, "get_process_id", get_process_id);
}

NODE_MODULE(addon, init)
