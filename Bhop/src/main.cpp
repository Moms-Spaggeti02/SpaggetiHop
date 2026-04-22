#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#pragma comment(lib, "psapi.lib")

// manual-map launcher.
// dll is baked in as an RCDATA resource, we map it into cs2 ourselves.
// never drops to disk, never calls LoadLibrary on it.

struct ManualMapData {
	uintptr_t imageBase;
	uintptr_t ntHeaders;
	uintptr_t pLoadLibraryA;
	uintptr_t pGetProcAddress;
	uintptr_t pRtlAddFunctionTable;
};

// this runs inside cs2. no external data, no imports other than what's
// in ManualMapData.
//
// stuck in its own section so the linker can't reorder it, ICF-fold it,
// or slip /INCREMENTAL trampolines between Shellcode and ShellcodeEnd.
#pragma section(".sc", read, execute)
#pragma runtime_checks("", off)
#pragma optimize("", off)

__declspec(code_seg(".sc$a"))
void __stdcall Shellcode(ManualMapData* pData) {
	if (!pData) return;

	auto* base = reinterpret_cast<uint8_t*>(pData->imageBase);
	auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(pData->ntHeaders);
	auto* opt  = &nt->OptionalHeader;

	auto _LoadLibraryA   = reinterpret_cast<decltype(&LoadLibraryA)>(pData->pLoadLibraryA);
	auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(pData->pGetProcAddress);
	using fnRtlAddFunctionTable = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
	auto _RtlAddFunctionTable   = reinterpret_cast<fnRtlAddFunctionTable>(pData->pRtlAddFunctionTable);

	// 1) relocs
	auto delta = reinterpret_cast<uintptr_t>(base) - opt->ImageBase;
	if (delta) {
		auto* relocDir = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (relocDir->Size) {
			auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + relocDir->VirtualAddress);
			while (reloc->VirtualAddress) {
				uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
				auto*    list  = reinterpret_cast<uint16_t*>(reloc + 1);
				for (uint32_t i = 0; i < count; i++) {
					uint16_t type   = list[i] >> 12;
					uint16_t offset = list[i] & 0xFFF;
					if (type == IMAGE_REL_BASED_DIR64) {
						*reinterpret_cast<uintptr_t*>(base + reloc->VirtualAddress + offset) += delta;
					} else if (type == IMAGE_REL_BASED_HIGHLOW) {
						*reinterpret_cast<uint32_t*>(base + reloc->VirtualAddress + offset) += static_cast<uint32_t>(delta);
					}
				}
				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
			}
		}
	}

	// 2) imports
	auto* importDir = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir->Size) {
		auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir->VirtualAddress);
		while (desc->Name) {
			char*   modName = reinterpret_cast<char*>(base + desc->Name);
			HMODULE hMod    = _LoadLibraryA(modName);
			if (hMod) {
				auto* thunk     = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
				auto* origThunk = desc->OriginalFirstThunk
					? reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk)
					: thunk;
				while (origThunk->u1.AddressOfData) {
					if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
						thunk->u1.Function = reinterpret_cast<uintptr_t>(
							_GetProcAddress(hMod, reinterpret_cast<char*>(IMAGE_ORDINAL(origThunk->u1.Ordinal))));
					} else {
						auto* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
						thunk->u1.Function = reinterpret_cast<uintptr_t>(
							_GetProcAddress(hMod, import->Name));
					}
					++thunk;
					++origThunk;
				}
			}
			++desc;
		}
	}

	// 3) x64 exception tables (MinHook trampolines blow up without this)
	auto* exceptDir = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (exceptDir->Size && _RtlAddFunctionTable) {
		auto* funcs = reinterpret_cast<PRUNTIME_FUNCTION>(base + exceptDir->VirtualAddress);
		DWORD count = exceptDir->Size / sizeof(RUNTIME_FUNCTION);
		_RtlAddFunctionTable(funcs, count, reinterpret_cast<DWORD64>(base));
	}

	// 4) TLS callbacks
	auto* tlsDir = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDir->Size) {
		auto* tls       = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + tlsDir->VirtualAddress);
		auto* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
		if (callbacks) {
			while (*callbacks) {
				(*callbacks)(base, DLL_PROCESS_ATTACH, nullptr);
				++callbacks;
			}
		}
	}

	// 5) and finally DllMain
	if (opt->AddressOfEntryPoint) {
		using fnDllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
		auto dllMain = reinterpret_cast<fnDllMain>(base + opt->AddressOfEntryPoint);
		dllMain(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr);
	}
}

__declspec(code_seg(".sc$b"))
void ShellcodeEnd() {}

#pragma optimize("", on)
#pragma runtime_checks("", restore)

// logging. prints to console + writes to a log file next to the exe.
// file gets wiped on each OpenLog() so we only keep the latest run.
static FILE* g_logFile = nullptr;

static void OpenLog() {
	char path[MAX_PATH] = {};
	const char* logName = "bhop_inject.log";
	if (GetModuleFileNameA(nullptr, path, MAX_PATH)) {
		char* slash = strrchr(path, '\\');
		if (slash && (slash + 1 - path) + strlen(logName) < MAX_PATH)
			strcpy_s(slash + 1, MAX_PATH - (slash + 1 - path), logName);
		else
			strcpy_s(path, MAX_PATH, logName);
	} else {
		strcpy_s(path, MAX_PATH, logName);
	}
	fopen_s(&g_logFile, path, "w");
}

static void CloseLog() {
	if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
}

// VT enable + the dash-wave animation
static void EnableVT() {
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	if (h == INVALID_HANDLE_VALUE) return;
	DWORD mode = 0;
	if (!GetConsoleMode(h, &mode)) return;
	SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

// animation runs on its own thread so the main wait-for-cs2 loop can
// keep sleeping without making it stutter. flip g_animRun to 0 when
// cs2 shows up (or on shutdown).
static volatile long g_animRun = 0;

static DWORD WINAPI AnimateThread(LPVOID) {
	// dashes bouncing between two rows. one per column, offset phase per column.
	constexpr int WIDTH  = 42;
	constexpr int PERIOD = 8;
	char top[WIDTH + 1]; top[WIDTH] = 0;
	char bot[WIDTH + 1]; bot[WIDTH] = 0;

	// reserve two rows, subsequent frames just overwrite them
	fputs("\n\n", stdout);
	fflush(stdout);

	int tick = 0;
	while (g_animRun) {
		for (int c = 0; c < WIDTH; ++c) {
			int  phase = (c + tick) % PERIOD;
			bool up    = phase < PERIOD / 2;
			top[c] = up ? '-' : ' ';
			bot[c] = up ? ' ' : '-';
		}
		// 2A = up 2, 2K = clear line, 38;2;R;G;B = truecolor fg, 0m = reset
		fprintf(stdout,
			"\x1b[2A\x1b[2K\x1b[38;2;255;105;180m%s\n\x1b[2K%s\x1b[0m\n",
			top, bot);
		fflush(stdout);
		++tick;
		Sleep(70);
	}

	// clear the two rows so we don't leave dashes sitting above later logs
	fputs("\x1b[2A\x1b[2K\n\x1b[2K\n", stdout);
	fflush(stdout);
	return 0;
}

static void Log(const char* fmt, ...) {
	va_list a;
	va_start(a, fmt);
	vprintf(fmt, a);
	va_end(a);
	fflush(stdout);

	if (g_logFile) {
		va_start(a, fmt);
		vfprintf(g_logFile, fmt, a);
		va_end(a);
		fflush(g_logFile);
	}
}

// pull the embedded dll out of our own PE. ID 101 matches the Bhop.rc RCDATA entry.
static bool LoadEmbeddedDLL(const uint8_t*& outBytes, size_t& outSize) {
	HRSRC hRes = FindResourceA(nullptr, MAKEINTRESOURCEA(101), reinterpret_cast<LPCSTR>(RT_RCDATA));
	if (!hRes) {
		Log("[!] FindResource failed: %lu\n", GetLastError());
		return false;
	}
	HGLOBAL hData = LoadResource(nullptr, hRes);
	if (!hData) {
		Log("[!] LoadResource failed: %lu\n", GetLastError());
		return false;
	}
	outBytes = reinterpret_cast<const uint8_t*>(LockResource(hData));
	outSize  = SizeofResource(nullptr, hRes);
	if (!outBytes || !outSize) {
		Log("[!] Embedded DLL resource is empty\n");
		return false;
	}
	return true;
}

// process / module helpers
static DWORD GetProcessIdByName(const wchar_t* name) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32W pe{};
	pe.dwSize = sizeof(pe);

	DWORD pid = 0;
	if (Process32FirstW(snap, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, name) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(snap, &pe));
	}
	CloseHandle(snap);
	return pid;
}

static bool WaitForRemoteModules(HANDLE hProc, const wchar_t* const* names, int count, DWORD timeoutMs) {
	const DWORD start = GetTickCount();
	std::vector<HMODULE> mods(1024);

	for (;;) {
		DWORD cbNeeded = 0;
		if (!EnumProcessModules(hProc, mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &cbNeeded)) {
			Sleep(100);
			if (GetTickCount() - start > timeoutMs) return false;
			continue;
		}
		if (cbNeeded > mods.size() * sizeof(HMODULE)) {
			mods.resize(cbNeeded / sizeof(HMODULE));
			continue;
		}

		int found = 0;
		for (int i = 0; i < count; i++) {
			for (DWORD j = 0; j < cbNeeded / sizeof(HMODULE); j++) {
				wchar_t modPath[MAX_PATH];
				if (GetModuleFileNameExW(hProc, mods[j], modPath, MAX_PATH)) {
					const wchar_t* slash = wcsrchr(modPath, L'\\');
					const wchar_t* base  = slash ? slash + 1 : modPath;
					if (_wcsicmp(base, names[i]) == 0) { ++found; break; }
				}
			}
		}
		if (found == count) return true;

		if (GetTickCount() - start > timeoutMs) return false;
		Sleep(200);
	}
}

// manual-map guts
static bool ManualMap(HANDLE hProc, const uint8_t* raw, size_t rawSize) {
	if (rawSize < sizeof(IMAGE_DOS_HEADER)) {
		Log("[!] DLL bytes too small\n");
		return false;
	}
	auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		Log("[!] Invalid DOS signature\n");
		return false;
	}
	auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		Log("[!] Invalid NT signature\n");
		return false;
	}
	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		Log("[!] Embedded DLL is not x64\n");
		return false;
	}

	const DWORD imageSize = nt->OptionalHeader.SizeOfImage;

	void* remoteBase = VirtualAllocEx(hProc, nullptr, imageSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteBase) {
		Log("[!] VirtualAllocEx(image) failed: %lu\n", GetLastError());
		return false;
	}
	Log("[+] Image alloc @ %p (0x%X bytes)\n", remoteBase, imageSize);

	if (!WriteProcessMemory(hProc, remoteBase, raw, nt->OptionalHeader.SizeOfHeaders, nullptr)) {
		Log("[!] WriteProcessMemory(headers) failed: %lu\n", GetLastError());
		VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
		return false;
	}

	auto* section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
		if (section->SizeOfRawData == 0) continue;
		if (!WriteProcessMemory(hProc,
				reinterpret_cast<uint8_t*>(remoteBase) + section->VirtualAddress,
				raw + section->PointerToRawData,
				section->SizeOfRawData, nullptr)) {
			Log("[!] WriteProcessMemory(section %.8s) failed: %lu\n",
				section->Name, GetLastError());
			VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
			return false;
		}
	}
	Log("[+] Wrote %d sections\n", nt->FileHeader.NumberOfSections);

	ManualMapData data{};
	data.imageBase = reinterpret_cast<uintptr_t>(remoteBase);
	data.ntHeaders = reinterpret_cast<uintptr_t>(remoteBase) + dos->e_lfanew;

	HMODULE hK32   = GetModuleHandleW(L"kernel32.dll");
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	data.pLoadLibraryA        = reinterpret_cast<uintptr_t>(GetProcAddress(hK32, "LoadLibraryA"));
	data.pGetProcAddress      = reinterpret_cast<uintptr_t>(GetProcAddress(hK32, "GetProcAddress"));
	data.pRtlAddFunctionTable = reinterpret_cast<uintptr_t>(GetProcAddress(hK32, "RtlAddFunctionTable"));
	if (!data.pRtlAddFunctionTable)
		data.pRtlAddFunctionTable = reinterpret_cast<uintptr_t>(GetProcAddress(hNtdll, "RtlAddFunctionTable"));

	const size_t shellcodeSize = reinterpret_cast<uintptr_t>(&ShellcodeEnd) - reinterpret_cast<uintptr_t>(&Shellcode);
	if (shellcodeSize == 0 || shellcodeSize > 0x4000) {
		Log("[!] Shellcode size implausible (%zu), linker layout issue\n", shellcodeSize);
		VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
		return false;
	}

	const size_t totalSize = sizeof(ManualMapData) + shellcodeSize + 64;
	void* remoteStub = VirtualAllocEx(hProc, nullptr, totalSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteStub) {
		Log("[!] VirtualAllocEx(stub) failed: %lu\n", GetLastError());
		VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
		return false;
	}

	auto* remoteData = reinterpret_cast<uint8_t*>(remoteStub);
	auto* remoteCode = remoteData + sizeof(ManualMapData);

	if (!WriteProcessMemory(hProc, remoteData, &data, sizeof(data), nullptr)
		|| !WriteProcessMemory(hProc, remoteCode, reinterpret_cast<void*>(&Shellcode), shellcodeSize, nullptr)) {
		Log("[!] WriteProcessMemory(stub) failed: %lu\n", GetLastError());
		VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, remoteStub, 0, MEM_RELEASE);
		return false;
	}
	Log("[+] Stub written (%zu bytes shellcode)\n", shellcodeSize);

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteCode), remoteData, 0, nullptr);
	if (!hThread) {
		Log("[!] CreateRemoteThread failed: %lu\n", GetLastError());
		VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, remoteStub, 0, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(hThread, 10000);
	CloseHandle(hThread);

	// stub only runs once, free it. leave the image alone.
	VirtualFreeEx(hProc, remoteStub, 0, MEM_RELEASE);
	return true;
}

// entry
int main() {
	SetConsoleTitleA("SpaggetiHop");
	OpenLog();

	EnableVT();

	// banner, hot pink (255,105,180). closing \x1b[0m resets the color.
	static const char* banner =
		"\x1b[38;2;255;105;180m"
		R"(
   _____                              __  _ __  __
  / ___/____  ____ _____ _____ ____  / /_(_) / / /___  ____      __      __
  \__ \/ __ \/ __ `/ __ `/ __ `/ _ \/ __/ / /_/ / __ \/ __ \  __/ /_  __/ /_
 ___/ / /_/ / /_/ / /_/ / /_/ /  __/ /_/ / __  / /_/ / /_/ / /_  __/ /_  __/
/____/ .___/\__,_/\__, /\__, /\___/\__/_/_/ /_/\____/ .___/   /_/     /_/
    /_/          /____//____/                      /_/

 ______	 ______	 ______  ______	 ______	 ______	 ______	 ______	 ______	 ______
/_____/	/_____/	/_____/ /_____/	/_____/	/_____/	/_____/	/_____/	/_____/	/_____/

)"
		"\x1b[0m\n";
	fputs(banner, stdout);
	fflush(stdout);

	const uint8_t* dllBytes = nullptr;
	size_t dllSize = 0;
	if (!LoadEmbeddedDLL(dllBytes, dllSize)) {
		Log("[!] no embedded DLL, rebuild the solution\n");
		system("pause");
		return 1;
	}
	Log("[+] embedded DLL: %zu bytes\n", dllSize);
	Log("[*] waiting for cs2.exe...\n");

	// start the wave *after* all the pre-wait log lines, otherwise stdout
	// writes race with the worker redrawing frames. only spins during the
	// quiet "waiting for cs2" part.
	g_animRun = 1;
	HANDLE hAnim = CreateThread(nullptr, 0, AnimateThread, nullptr, 0, nullptr);

	DWORD pid = 0;
	for (int i = 0; i < 600; i++) { // ~5 min
		pid = GetProcessIdByName(L"cs2.exe");
		if (pid) break;
		Sleep(500);
	}

	// kill the animation and wait for it to clean up its rows before we log again
	g_animRun = 0;
	if (hAnim) { WaitForSingleObject(hAnim, 500); CloseHandle(hAnim); }

	if (!pid) {
		Log("[!] cs2.exe not found within timeout\n");
		system("pause");
		return 1;
	}
	Log("[+] cs2.exe PID=%lu\n", pid);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc) {
		Log("[!] OpenProcess failed: %lu (try admin)\n", GetLastError());
		system("pause");
		return 1;
	}

	Log("[*] waiting for client.dll + engine2.dll...\n");
	const wchar_t* wanted[] = { L"client.dll", L"engine2.dll" };
	if (!WaitForRemoteModules(hProc, wanted, 2, 120000)) {
		Log("[!] client.dll / engine2.dll did not load within 2 minutes\n");
		CloseHandle(hProc);
		system("pause");
		return 1;
	}
	Log("[+] target modules ready\n");

	if (!ManualMap(hProc, dllBytes, dllSize)) {
		CloseHandle(hProc);
		system("pause");
		return 1;
	}

	CloseHandle(hProc);
	Log("[+] injected, closing launcher (DLL console stays)\n");
	Sleep(400);
	CloseLog();
	FreeConsole();
	return 0;
}
