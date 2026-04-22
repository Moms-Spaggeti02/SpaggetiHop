#include <Windows.h>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#include "../rcs/MinHook/MinHook.h"
#include "../rcs/SDK.h"

static const char* SIG_CREATE_MOVE = "48 8B C4 4C 89 40 ?? 48 89 48 ?? 55 53 41 54";

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

	char        path[MAX_PATH] = {};
	const char* logName        = "bhop_error.log";
	if (g_hMod && GetModuleFileNameA(g_hMod, path, MAX_PATH)) {
		if (char* slash = strrchr(path, '\\'); slash && (slash + 1 - path) + strlen(logName) < MAX_PATH)
			strcpy_s(slash + 1, MAX_PATH - (slash + 1 - path), logName);
		else
			strcpy_s(path, MAX_PATH, logName);
	} else {
		strcpy_s(path, MAX_PATH, logName);
	}

	FILE* f = nullptr;
	fopen_s(&f, path, "w");
	if (!f)
		return;
	va_start(a, fmt);
	vfprintf(f, fmt, a);
	va_end(a);
	fclose(f);
}

static uintptr_t PatternScan(const uintptr_t base, const size_t size, const char* sig) {
	constexpr size_t MAX_TOKENS = 256;
	uint8_t          bytes[MAX_TOKENS];
	bool             wild[MAX_TOKENS];
	size_t           n = 0;

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
			LogError("[!] PatternScan: sig exceeds %zu-byte limit, truncated at '%s'\n", MAX_TOKENS, p);
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
			LogError("[!] PatternScan: odd-length or non-hex token at offset %td ('%c%c')\n", p - sig,
			         p[0] ? p[0] : '?', p[1] ? p[1] : '?');
			return 0;
		}
		wild[n]    = false;
		bytes[n++] = static_cast<uint8_t>(hex(p[0]) << 4 | hex(p[1]));
		p += 2;
	}
	if (n == 0) {
		LogError("[!] PatternScan: empty pattern\n");
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

uintptr_t    g_clientBase = 0;
uintptr_t    g_engineBase = 0;
fnCreateMove oCreateMove  = nullptr;
uint32_t*    g_pForceJump = nullptr;
void**       g_pNGC       = nullptr; // &CNetworkGameClient*

// two ways we can unload: user hit END, or DllMain got DETACH'd.
// DETACH runs under the loader lock so FreeConsole/fclose/FreeLibrary
// will deadlock. gotta skip cleanup in that case.
enum UnloadReason : int {
	UNLOAD_NONE   = 0,
	UNLOAD_USER   = 1,
	UNLOAD_DETACH = 2
};

volatile long g_unloadReason = UNLOAD_NONE;

// one state change per server tick, no matter how many CreateMove calls.
static int  g_lastBhopTick = -1;
// fallback toggle when pawn/ground can't be resolved (warmup, respawn, etc).
// keeps us at old-tick-flip behavior instead of going silent.
static bool g_tickFlip = false;

// autostrafe config. exposed as plain statics so we can tune without rebuild.
// STAMINA_CAP: skip a jump when stamina is above this (gives consistent max
// jump height / horizontal preservation). 0 = never skip, 100 = always.
// YAW_DEADZONE: minimum per-tick yaw delta (deg) to trigger auto-strafe, filters
// mouse jitter.
// CMD_MAX_MOVE: the magnitude we push into the cmd move fields (engine clamps
// to sv_maxspeed anyway, 450 is the conventional full-press value).
static constexpr float STAMINA_CAP  = 50.0f;
static constexpr float YAW_DEADZONE = 0.25f;
static constexpr float CMD_MAX_MOVE = 450.0f;

// diagnostic throttle.
static int g_lastDiagTick = -1;

// pull the local pawn off the entity table. handle is at client+dwLocalPlayerPawn,
// table layout: pages of 512 x 120-byte slots. returns null when not in a match.
static void* ResolveLocalPawn() {
	void* entSys = *reinterpret_cast<void**>(g_clientBase + offsets::dwEntityList);
	if (!entSys)
		return nullptr;
	const uint32_t handle = *reinterpret_cast<uint32_t*>(g_clientBase + offsets::dwLocalPlayerPawn);
	if (handle == UINT32_MAX)
		return nullptr;
	const uint32_t  listIdx = (handle & 0x7FFF) >> 9;
	const uintptr_t chunk   = *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(entSys) + 0x10 * listIdx + 0x8);
	if (!chunk)
		return nullptr;
	return *reinterpret_cast<void**>(chunk + 120 * (handle & 0x1FF));
}

// don't intercept while alt-tabbed or typing in the console / menu.
static bool GameHasFocus() {
	const HWND fg  = GetForegroundWindow();
	DWORD      pid = 0;
	GetWindowThreadProcessId(fg, &pid);
	return pid == GetCurrentProcessId();
}

// gather everything we read off the pawn/mvs once per hook call so pre- and
// post-phase share the same snapshot instead of re-walking the entity table.
struct TickSnapshot {
	void*    pawn     = nullptr;
	void*    mvs      = nullptr;
	bool     onGround = false;
	bool     valid    = false;
	float    speed2d  = 0.0f;
	float    yawVel   = 0.0f;
	float    stamina  = 0.0f;
	uint32_t flags    = 0;
};

static TickSnapshot ReadTickSnapshot() {
	TickSnapshot s{};
	s.pawn = ResolveLocalPawn();
	if (!s.pawn)
		return s;

	auto* pawnB = static_cast<uint8_t*>(s.pawn);
	s.flags     = *reinterpret_cast<uint32_t*>(pawnB + offsets::m_fFlags);
	const uint32_t hGround = *reinterpret_cast<uint32_t*>(pawnB + offsets::m_hGroundEntity);
	s.onGround  = (s.flags & offsets::FL_ONGROUND) != 0 || hGround != UINT32_MAX;

	const float* vel = reinterpret_cast<const float*>(pawnB + offsets::m_vecVelocity);
	s.speed2d = std::sqrt(vel[0] * vel[0] + vel[1] * vel[1]);

	// QAngle layout: [0]=pitch, [1]=yaw, [2]=roll. yaw-velocity drives autostrafe.
	const float* angVel = reinterpret_cast<const float*>(pawnB + offsets::m_angEyeAnglesVelocity);
	s.yawVel = angVel[1];

	s.mvs = *reinterpret_cast<void**>(pawnB + offsets::m_pMovementServices);
	if (s.mvs) {
		// stamina lives on CCSPlayer_MovementServices (subclass). offset is valid
		// for CS players - this DLL only targets CS2 so every local pawn is one.
		s.stamina = *reinterpret_cast<const float*>(static_cast<uint8_t*>(s.mvs) + offsets::m_flStamina);
	}
	s.valid = true;
	return s;
}

// autostrafe: while airborne and player is turning their view, write the
// matching strafe direction into the cmd's move fields so the engine applies
// optimal air-accel. perpendicular wishdir maxes air-acceleration since the
// dot(vel, wish) term goes to zero and add_speed hits the airaccel cap.
//
// driven by m_angEyeAnglesVelocity.y so it tracks actual mouse movement rather
// than auto-zigzagging (which would look obviously bot-like). no mouse input
// -> no override, original move values pass through.
//
// run BEFORE oCreateMove so our values are what the cmd-builder reads. the
// cmd ships to the server with our sidemove, server applies the same airaccel
// we predict client-side, so no prediction desync + no CRC issue (we're not
// mutating the cmd itself, just the pre-cmd inputs the builder pulls from).
static void ApplyAutostrafe(const TickSnapshot& s) {
	if (!s.valid || !s.mvs || s.onGround)
		return;

	float side = 0.0f;
	if (s.yawVel > YAW_DEADZONE)
		side = +CMD_MAX_MOVE; // turning right
	else if (s.yawVel < -YAW_DEADZONE)
		side = -CMD_MAX_MOVE; // turning left
	else
		return; // player isn't steering -> leave their input alone

	auto* mvsB = static_cast<uint8_t*>(s.mvs);
	// write BOTH the cmd-staging value (read by the builder for cmd.sidemove)
	// AND the physics-consumed value so any immediate prediction step lines up.
	*reinterpret_cast<float*>(mvsB + offsets::m_flCmdLeftMove) = side;
	*reinterpret_cast<float*>(mvsB + offsets::m_flLeftMove)    = side;
}

static void __fastcall hkCreateMove(const uintptr_t pThis, const unsigned slot, const uintptr_t cmd) {
	const bool held = (GetAsyncKeyState(VK_SPACE) & 0x8000) != 0 && GameHasFocus();

	// snapshot state once - both phases use it.
	const TickSnapshot snap = ReadTickSnapshot();

	// ===== PRE-PHASE: autostrafe (writes must land before cmd-builder reads) =====
	if (held)
		ApplyAutostrafe(snap);

	// ===== ORIGINAL: engine builds this tick's cmd, including our strafe =====
	oCreateMove(pThis, slot, cmd);

	// ===== POST-PHASE: stage dwForceJump for next tick's cmd =====
	if (!held) {
		*g_pForceJump  = FJ_RELEASE;
		g_lastBhopTick = -1;
		g_tickFlip     = false;
		return;
	}

	void* ngc = *g_pNGC;
	if (!ngc)
		return;
	const int tick = *reinterpret_cast<int*>(static_cast<uint8_t*>(ngc) + offsets::dwNetworkGameClient_clientTick);
	if (tick == g_lastBhopTick)
		return;
	g_lastBhopTick = tick;

	// primary path: pawn reachable, use real ground + stamina gating.
	if (snap.valid) {
		if (snap.onGround) {
			// stamina gate: a fresh bhop just landed with high stamina loses a
			// chunk of horizontal velocity via m_flVelMulAtJumpStart. skipping
			// the next jump for a tick lets stamina decay, so the NEXT jump
			// preserves full horizontal speed. net: chain at slightly lower
			// cadence but much higher max speed.
			if (snap.stamina > STAMINA_CAP) {
				*g_pForceJump = FJ_RELEASE;
			} else if (snap.mvs) {
				// subtick precision: emit jump edge at tick-fraction 0.0 so we
				// don't waste the fraction between ground contact and the
				// engine's default (late) subtick slot.
				float* arr = reinterpret_cast<float*>(static_cast<uint8_t*>(snap.mvs) +
				                                     offsets::m_arrForceSubtickMoveWhen);
				arr[0] = arr[1] = arr[2] = arr[3] = 0.0f;
				*g_pForceJump = FJ_PRESS;
			} else {
				*g_pForceJump = FJ_PRESS;
			}
		} else {
			*g_pForceJump = FJ_RELEASE;
		}
		g_tickFlip = false;

		// periodic diagnostics (~1/sec at 64 tick). log shows up in our console
		// so the user can see what bhop is seeing without needing an external
		// velocity hud.
		if (tick - g_lastDiagTick >= 64 || g_lastDiagTick < 0) {
			g_lastDiagTick = tick;
			Log("[bhop] spd=%5.1f stam=%5.1f yawv=%+6.2f %s\n",
			    snap.speed2d, snap.stamina, snap.yawVel, snap.onGround ? "GND" : "AIR");
		}
		return;
	}

	// fallback: pawn unreachable (pre-match, mid-respawn, loading). old
	// alternating flip so at least we get the CSGO-era ~50% bhop rate
	// instead of silence.
	g_tickFlip    = !g_tickFlip;
	*g_pForceJump = g_tickFlip ? FJ_PRESS : FJ_RELEASE;
}

static DWORD WINAPI MainThread(const LPVOID hMod) {
	AllocConsole();
	freopen_s(&g_console, "CONOUT$", "w", stdout);
	Log("[bhop] loaded1\n");

	HMODULE client;
	while (!((client = GetModuleHandleA("client.dll"))))
		Sleep(100);
	HMODULE engine;
	while (!((engine = GetModuleHandleA("engine2.dll"))))
		Sleep(100);

	g_clientBase      = reinterpret_cast<uintptr_t>(client);
	g_engineBase      = reinterpret_cast<uintptr_t>(engine);
	const size_t size = ModuleSize(g_clientBase);

	Log("[bhop] modules resolved\n");

	g_pForceJump = reinterpret_cast<uint32_t*>(g_clientBase + offsets::dwForceJump);
	g_pNGC       = reinterpret_cast<void**>(g_engineBase + offsets::dwNetworkGameClient);

	const uintptr_t cmAddr = PatternScan(g_clientBase, size, SIG_CREATE_MOVE);
	if (!cmAddr) {
		LogError("[!] CreateMove sig miss\n");
		return 1;
	}
	Log("[bhop] CreateMove @ client+0x%llx\n", static_cast<unsigned long long>(cmAddr - g_clientBase));

	if (MH_Initialize() != MH_OK) {
		Log("[!] MH_Initialize\n");
		return 1;
	}
	if (MH_CreateHook(reinterpret_cast<LPVOID>(cmAddr), &hkCreateMove, reinterpret_cast<LPVOID*>(&oCreateMove)) !=
	    MH_OK) {
		Log("[!] MH_CreateHook\n");
		return 1;
	}
	if (MH_EnableHook(reinterpret_cast<LPVOID>(cmAddr)) != MH_OK) {
		Log("[!] MH_EnableHook\n");
		return 1;
	}
	Log("[bhop] hook ON, SPACE=bhop, END=unload\n");

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
	Log("[bhop] unloaded\n");
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
