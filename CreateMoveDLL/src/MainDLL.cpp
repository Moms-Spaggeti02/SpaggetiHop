#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#include "../rcs/MinHook/MinHook.h"
#include "../rcs/SDK.h"
#include "../rcs/obf.h"

// sig is split in two so the whole pattern isn't sitting in .rdata.
// glued back together on the stack inside MainThread.

constexpr uint32_t FJ_PRESS   = 65537; // 0x10001
constexpr uint32_t FJ_RELEASE = 256;   // 0x100

FILE*   g_console = nullptr;
HMODULE g_hMod    = nullptr;

void Log(const char* fmt, ...) {
	if (!g_console)
		return;
	va_list a;
	va_start(a, fmt);
	vfprintf(g_console, fmt, a);
	va_end(a);
	fflush(g_console);
}

// dumps the last error to a file next to the dll. overwrites every call,
// only keep the most recent one. still there after the console closes.
static void LogError(const char* fmt, ...) {
	va_list a;
	va_start(a, fmt);
	if (g_console) {
		vfprintf(g_console, fmt, a);
		fflush(g_console);
	}
	va_end(a);

	char path[MAX_PATH] = {};
	const auto logName = OBF("bhop_error.log");
	if (g_hMod && GetModuleFileNameA(g_hMod, path, MAX_PATH)) {
		if (char* slash = strrchr(path, '\\'); slash && (slash + 1 - path) + strlen(logName) < MAX_PATH)
			strcpy_s(slash + 1, MAX_PATH - (slash + 1 - path), logName);
		else
			strcpy_s(path, MAX_PATH, logName);
	} else {
		strcpy_s(path, MAX_PATH, logName);
	}

	FILE* f = nullptr;
	const auto mode = OBF("w");
	fopen_s(&f, path, mode);
	if (!f)
		return;
	va_start(a, fmt);
	vfprintf(f, fmt, a);
	va_end(a);
	fclose(f);
}

static uintptr_t PatternScan(const uintptr_t base, const size_t size, const char* sig) {
	constexpr size_t MAX_TOKENS = 256;
	uint8_t bytes[MAX_TOKENS];
	bool    wild[MAX_TOKENS];
	size_t  n = 0;

	auto isHex = [](const char c) -> bool {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
	};
	auto hex = [](const char c) -> uint8_t {
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'A' && c <= 'F')
			return c - 'A' + 10;
		if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;
		return 0;
	};

	for (const char* p = sig; *p;) {
		if (n >= MAX_TOKENS) {
			LogError(OBF("[!] PatternScan: sig exceeds %zu-byte limit, truncated at '%s'\n"),
				MAX_TOKENS, p);
			return 0;
		}
		if (*p == ' ') {
			++p;
			continue;
		}
		if (*p == '?') {
			wild[n]  = true;
			bytes[n] = 0;
			++n;
			++p;
			if (*p == '?')
				++p;
			continue;
		}
		if (!isHex(p[0]) || !isHex(p[1])) {
			LogError(OBF("[!] PatternScan: odd-length or non-hex token at offset %td ('%c%c')\n"),
				p - sig, p[0] ? p[0] : '?', p[1] ? p[1] : '?');
			return 0;
		}
		wild[n]    = false;
		bytes[n++] = static_cast<uint8_t>(hex(p[0]) << 4 | hex(p[1]));
		p += 2;
	}
	if (n == 0) {
		LogError(OBF("[!] PatternScan: empty pattern\n"));
		return 0;
	}

	const auto* mem = reinterpret_cast<uint8_t*>(base);
	for (size_t i = 0; i + n <= size; ++i) {
		bool ok = true;
		for (size_t j = 0; j < n; ++j)
			if (!wild[j] && mem[i + j] != bytes[j]) {
				ok = false;
				break;
			}
		if (ok)
			return base + i;
	}
	return 0;
}

size_t ModuleSize(const uintptr_t base) {
	const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	const auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
	return nt->OptionalHeader.SizeOfImage;
}

using fnCreateMove = void(__fastcall*)(uintptr_t, unsigned, uintptr_t);

uintptr_t     g_clientBase = 0;
uintptr_t     g_engineBase = 0;
fnCreateMove  oCreateMove  = nullptr;
uint32_t*     g_pForceJump = nullptr;
void**        g_pNGC       = nullptr; // &CNetworkGameClient*

// two ways we can unload: user hit END, or DllMain got DETACH'd.
// DETACH runs under the loader lock so FreeConsole/fclose/FreeLibrary
// will deadlock. gotta skip cleanup in that case.
enum UnloadReason : int { UNLOAD_NONE = 0, UNLOAD_USER = 1, UNLOAD_DETACH = 2 };
volatile long g_unloadReason = UNLOAD_NONE;

// read the tick counter, flip PRESS/RELEASE whenever it changes.
// one state per tick, no misfires.
static bool g_jumpActive = false;
static int  g_lastTick   = -1;

static void __fastcall hkCreateMove(const uintptr_t pThis, const unsigned slot, const uintptr_t cmd) {
	oCreateMove(pThis, slot, cmd);

	const bool space = (GetAsyncKeyState(VK_SPACE) & 0x8000) != 0;
	if (!space) {
		*g_pForceJump = FJ_RELEASE;
		g_jumpActive  = false;
		g_lastTick    = -1;
		return;
	}

	void* ngc = *g_pNGC;
	if (!ngc) return;
	const int tick = *reinterpret_cast<int*>(static_cast<uint8_t*>(ngc) + offsets::dwNetworkGameClient_clientTick);

	if (tick == g_lastTick)
		return;
	g_lastTick = tick;

	*g_pForceJump = g_jumpActive ? FJ_RELEASE : FJ_PRESS;
	g_jumpActive  = !g_jumpActive;
}

static DWORD WINAPI MainThread(const LPVOID hMod) {
	AllocConsole();
	{
		const auto dev  = OBF("CONOUT$");
		const auto mode = OBF("w");
		freopen_s(&g_console, dev, mode, stdout);
	}
	Log(OBF("[bhop] loaded1\n"));

	// constexpr = hashed at compile time. the actual strings don't end up in the binary.
	constexpr uint32_t hClient = obf::hash(L"client.dll");
	constexpr uint32_t hEngine = obf::hash(L"engine2.dll");
	HMODULE client;
	while (!((client = obf::mod(hClient)))) Sleep(100);
	HMODULE engine;
	while (!((engine = obf::mod(hEngine)))) Sleep(100);

	g_clientBase = reinterpret_cast<uintptr_t>(client);
	g_engineBase = reinterpret_cast<uintptr_t>(engine);
	const size_t size  = ModuleSize(g_clientBase);

	Log(OBF("[bhop] modules resolved\n"));

	g_pForceJump = reinterpret_cast<uint32_t*>(g_clientBase + offsets::dwForceJump);
	g_pNGC       = reinterpret_cast<void**>(g_engineBase + offsets::dwNetworkGameClient);

	// stitch the sig back together on the stack, throw it away after.
	char sig[64];
	{
		const auto   h  = OBF("48 8B C4 4C 89 40 ?? 48 89");
		const auto   t  = OBF(" 48 ?? 55 53 41 54");
		const size_t hn = strlen(h);
		const size_t tn = strlen(t);
		memcpy(sig, h.buf, hn);
		memcpy(sig + hn, t.buf, tn + 1);
	}
	const uintptr_t cmAddr = PatternScan(g_clientBase, size, sig);
	if (!cmAddr) {
		LogError(OBF("[!] CreateMove sig miss\n"));
		return 1;
	}
	Log(OBF("[bhop] CreateMove @ client+0x%llx\n"), static_cast<unsigned long long>(cmAddr - g_clientBase));

	if (MH_Initialize() != MH_OK) {
		Log(OBF("[!] MH_Initialize\n"));
		return 1;
	}
	if (MH_CreateHook(reinterpret_cast<LPVOID>(cmAddr), &hkCreateMove, reinterpret_cast<LPVOID*>(&oCreateMove)) != MH_OK) {
		Log(OBF("[!] MH_CreateHook\n"));
		return 1;
	}
	if (MH_EnableHook(reinterpret_cast<LPVOID>(cmAddr)) != MH_OK) {
		Log(OBF("[!] MH_EnableHook\n"));
		return 1;
	}
	Log(OBF("[bhop] hook ON — SPACE=bhop, END=unload\n"));

	while (g_unloadReason == UNLOAD_NONE && !(GetAsyncKeyState(VK_END) & 0x8000))
		Sleep(50);

	// if END got us out, mark it USER. if DllMain already flagged DETACH,
	// don't touch it.
	InterlockedCompareExchange(&g_unloadReason, UNLOAD_USER, UNLOAD_NONE);

	MH_DisableHook(reinterpret_cast<LPVOID>(cmAddr));
	// give any in-flight hkCreateMove a moment to finish before we nuke
	// the trampoline pages
	Sleep(250);
	MH_Uninitialize();

	if (g_unloadReason == UNLOAD_DETACH) {
		// loader lock is held, anything fancy here deadlocks.
		// FreeLibraryAndExitThread is pointless too since we're already going away.
		// client.dll might be gone already so don't touch g_pForceJump either.
		return 0;
	}

	*g_pForceJump = FJ_RELEASE;
	Log(OBF("[bhop] unloaded\n"));
	if (g_console)
		fclose(g_console);
	FreeConsole();
	FreeLibraryAndExitThread(static_cast<HMODULE>(hMod), 0);
}

BOOL APIENTRY DllMain(const HMODULE hMod, const DWORD reason, LPVOID) {
	if (reason == DLL_PROCESS_ATTACH) {
		g_hMod = hMod;
		DisableThreadLibraryCalls(hMod);
		CreateThread(nullptr, 0, MainThread, hMod, 0, nullptr);
	} else if (reason == DLL_PROCESS_DETACH) {
		// loader lock is held here. bare minimum, get out.
		// MainThread checks this flag and skips the stuff that would hang.
		InterlockedExchange(&g_unloadReason, UNLOAD_DETACH);
	}
	return TRUE;
}