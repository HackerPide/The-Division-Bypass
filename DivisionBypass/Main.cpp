#include <stdio.h>
#include <tchar.h>

// Ignore the HANDLE to DWORD warnings
#pragma warning(disable : 4312 4311 4302 4244)

#include "nt_ddk.h"
#include "utils.h"

unsigned __int64 GetThreadAddressById(DWORD threadId)
{
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, false, threadId);
	if (hThread == NULL)
	{
		_tprintf(_T("Failed to open thread %d!\n"), threadId);
		return 0;
	}
			
	static HMODULE hNtDll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	static tNtQueryInformationThread NtQueryInformationThread = (tNtQueryInformationThread)Utils::GetProcAddress(hNtDll, "NtQueryInformationThread");
	unsigned __int64 retAddress = 0;
	NTSTATUS status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &retAddress, sizeof(unsigned __int64), NULL);
	if (!NT_SUCCESS(status))
	{
		_tprintf(_T("NtQueryInformationThread failed; NTSTATUS = 0x%X"), status);
		CloseHandle(hThread);
		return 0;
	}

	CloseHandle(hThread);
	return retAddress;
}

HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* Module, ULONG* ModuleSize)
{
	void* dwModuleHandle = 0;

	PPROCESS_BASIC_INFORMATION pbi = NULL;
	PEB peb;
	PEB_LDR_DATA peb_ldr;

	// Try to allocate buffer 
	HANDLE	hHeap = GetProcessHeap();
	DWORD dwSize = sizeof(PROCESS_BASIC_INFORMATION);
	pbi = (PPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSize);

	static HMODULE hNtDll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	static tNtQueryInformationProcess NtQueryInformationProcess = (tNtQueryInformationProcess)Utils::GetProcAddress(hNtDll, "NtQueryInformationProcess");

	ULONG dwSizeNeeded = 0;
	NTSTATUS dwStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, dwSize, &dwSizeNeeded);
	if (dwStatus >= 0 && dwSize < dwSizeNeeded)
	{
		if (pbi)
			HeapFree(hHeap, 0, pbi);

		pbi = (PPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSizeNeeded);
		if (!pbi)
		{
			#ifdef _DEBUG
			_tprintf(_T("Couldn't allocate heap buffer!\n"));
			#endif
			return NULL;
		}

		dwStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, dwSizeNeeded, &dwSizeNeeded);
	}

	// Did we successfully get basic info on process
	if (dwStatus >= 0)
	{
		// Read Process Environment Block (PEB)
		if (pbi->PebBaseAddress)
		{
			SIZE_T dwBytesRead = 0;
			if (ReadProcessMemory(hProcess, pbi->PebBaseAddress, &peb, sizeof(peb), &dwBytesRead))
			{
				dwBytesRead = 0;
				if (ReadProcessMemory(hProcess, peb.Ldr, &peb_ldr, sizeof(peb_ldr), &dwBytesRead))
				{
					LIST_ENTRY *pLdrListHead = (LIST_ENTRY *)peb_ldr.InLoadOrderModuleList.Flink;
					LIST_ENTRY *pLdrCurrentNode = peb_ldr.InLoadOrderModuleList.Flink;
					do
					{
						LDR_DATA_TABLE_ENTRY lstEntry = { 0 };
						dwBytesRead = 0;
						if (!ReadProcessMemory(hProcess, (void*)pLdrCurrentNode, &lstEntry, sizeof(LDR_DATA_TABLE_ENTRY), &dwBytesRead))
						{
							if (pbi)
								HeapFree(hHeap, 0, pbi);
							return NULL;
						}

						pLdrCurrentNode = lstEntry.InLoadOrderLinks.Flink;

						wchar_t wcsBaseDllName[MAX_PATH] = { 0 };
						char strBaseDllName[MAX_PATH] = { 0 };
						if (lstEntry.BaseDllName.Length > 0)
						{
							dwBytesRead = 0;
							if (ReadProcessMemory(hProcess, (LPCVOID)lstEntry.BaseDllName.Buffer, &wcsBaseDllName, lstEntry.BaseDllName.Length, &dwBytesRead))
							{
								size_t bytesCopied = 0;
								wcstombs_s(&bytesCopied, strBaseDllName, wcsBaseDllName, MAX_PATH);
							}
						}

						//wchar_t wcsFullDllName[MAX_PATH] = { 0 };
						//char strFullDllName[MAX_PATH] = { 0 };
						//if (lstEntry.FullDllName.Length > 0)
						//{
						//	dwBytesRead = 0;
						//	if (ReadProcessMemory(m_hProcess, (LPCVOID)lstEntry.FullDllName.Buffer, &wcsFullDllName, lstEntry.FullDllName.Length, &dwBytesRead))
						//	{
						//		size_t bytesCopied = 0;
						//		wcstombs_s(&bytesCopied, strFullDllName, wcsFullDllName, MAX_PATH);
						//	}
						//}

						if (lstEntry.DllBase != nullptr && lstEntry.SizeOfImage != 0)
						{
							if (_stricmp(strBaseDllName, Module) == 0)
							{
								dwModuleHandle = lstEntry.DllBase;
								if (ModuleSize)
									*ModuleSize = lstEntry.SizeOfImage;
								break;
							}
						}

					} while (pLdrListHead != pLdrCurrentNode);

				} // Get Ldr
			} // Read PEB 
		} // Check for PEB
	}

	if (pbi)
		HeapFree(hHeap, 0, pbi);

	return (HMODULE)dwModuleHandle;
}

DWORD GetProcessIdByName(const char* process)
{
	ULONG cbBuffer = 131072;
	void* pBuffer = NULL;
	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	void* hHeap = GetProcessHeap();

	DWORD processId_ = 0;

	static HMODULE hNtDll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	static tNtQuerySystemInformation NtQuerySystemInformation = (tNtQuerySystemInformation)Utils::GetProcAddress(hNtDll, "NtQuerySystemInformation");

	bool check = false;
	bool found = false;
	while (!found)
	{
		pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cbBuffer);
		if (pBuffer == NULL)
			return 0;

		Status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, cbBuffer, &cbBuffer);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			check = true;
			HeapFree(hHeap, NULL, pBuffer);
			cbBuffer *= 2;
		}
		else if (!NT_SUCCESS(Status))
		{
			HeapFree(hHeap, NULL, pBuffer);
			return 0;
		}
		else
		{
			check = false;

			PSYSTEM_PROCESS_INFORMATION infoP = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
			while (infoP)
			{
				char pName[256];
				memset(pName, 0, sizeof(pName));
				WideCharToMultiByte(0, 0, infoP->ImageName.Buffer, infoP->ImageName.Length, pName, 256, NULL, NULL);
				if (_stricmp(process, pName) == 0)
				{
					processId_ = (DWORD)infoP->UniqueProcessId;
					found = true;
					break;
				}

				if (!infoP->NextEntryOffset)
					break;
				infoP = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)infoP + infoP->NextEntryOffset);
			}
			if (pBuffer)
				HeapFree(hHeap, NULL, pBuffer);
		}

		if (processId_ != 0)
		{
			break;
		}
		else if (!check)
		{
			// Don't continuously search...
			break;
		}
	}

	return processId_;
}

bool TerminateIntegrityCheckThread(HANDLE hProcess)
{
	if (hProcess == NULL)
		return 0;

	bool terminated = false;
	NTSTATUS status;
	PVOID SystemProcessInfo;
	ULONG bufferSize = 0x4000;
	HANDLE hHeap = GetProcessHeap();
	DWORD ProcessId = GetProcessId(hProcess);

	static HMODULE hNtDll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	static tNtQuerySystemInformation NtQuerySystemInformation = (tNtQuerySystemInformation)Utils::GetProcAddress(hNtDll, "NtQuerySystemInformation");

	SystemProcessInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, bufferSize);

	while (TRUE)
	{
		status = NtQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, bufferSize, &bufferSize);
		if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (SystemProcessInfo)
				HeapFree(hHeap, 0, SystemProcessInfo);
			SystemProcessInfo = HeapAlloc(hHeap, HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, bufferSize * 2);
		}
		else
			break;
	}

	if (!NT_SUCCESS(status))
	{
		if (SystemProcessInfo)
			HeapFree(hHeap, 0, SystemProcessInfo);
		return 0;
	}

	PSYSTEM_PROCESS_INFORMATION process;
	PSYSTEM_THREAD_INFORMATION threads;
	ULONG numberOfThreads;

	process = PROCESS_INFORMATION_FIRST_PROCESS(SystemProcessInfo);
	do {
		if (process->UniqueProcessId == (HANDLE)ProcessId)
			break;
	} while (process = PROCESS_INFORMATION_NEXT_PROCESS(process));

	if (!process)
	{
		// The process doesn't exist anymore :(
		return 0;
	}

	void* mainModule = GetRemoteModuleHandle(hProcess, "thedivision.exe", NULL);
	threads = process->Threads;
	numberOfThreads = process->NumberOfThreads;

	// Look for new threads and update existing ones.
	for (ULONG i = 0; i < numberOfThreads; i++)
	{
		PSYSTEM_THREAD_INFORMATION thread = &threads[i];
		if (!thread)
			continue;
		DWORD thId = (DWORD)thread->ClientId.UniqueThread;
		if (!thId)
			continue;

		if (GetThreadAddressById(thId) == ((unsigned __int64)mainModule + 0x3C60))
		{
			_tprintf(_T("Thread found! Terminating!\n"));

			HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, thId);
			TerminateThread(hThread, 1);
			_tprintf(_T("Thread %d (0x%X) terminated!\n"), thId, thId);
			CloseHandle(hThread);
			terminated = true;
			break;
		}
	}

	if (SystemProcessInfo)
		HeapFree(hHeap, 0, SystemProcessInfo);

	return terminated;
}

int main()
{
	_tprintf(_T("**** The Division Bypass ****\nby dude719\n\n"));

	DWORD pid = GetProcessIdByName("thedivision.exe");
	if (pid)
	{
		_tprintf(_T("Found The Division with pid %d (0x%X)\n"), pid, pid);

		HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, (DWORD)pid);
		if (hProcess)
		{
			if (TerminateIntegrityCheckThread(hProcess))
			{
				_tprintf(_T("Successfully bypassed!\n"));
			}
		}
		else
		{
			_tprintf(_T("Failed to open The Division process! Try running as administrator...\n"));
		}
	}
	else
	{
		_tprintf(_T("Failed to find The Division process! \"thedivision.exe\" needs to be running first...\n"));
	}

	getchar();

	return 0;
}