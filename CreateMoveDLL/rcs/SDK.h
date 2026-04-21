#pragma once
#include <cstdint>
#include <Windows.h>

// CS2 offsets. these break every update, pull fresh ones from a2x / offsets.hpp.
// everything is relative to client.dll unless i say otherwise.
namespace offsets {
    // client.dll
    constexpr uintptr_t dwEntityList       = 0x24C9710; // CGameEntitySystem*
    constexpr uintptr_t dwLocalPlayerPawn  = 0x204F630; // CHandle<C_CSPlayerPawn>

    // C_BaseEntity netvar
    constexpr uintptr_t m_fFlags           = 0x400; // uint32

    // jump button state the engine reads.
    // press = 0x10001, release = 0x100.
    constexpr uintptr_t dwForceJump        = 0x2048DB0;

    // engine2.dll, CNetworkGameClient, used for tick sync
    constexpr uintptr_t dwNetworkGameClient            = 0x90A0C0;
    constexpr uintptr_t dwNetworkGameClient_clientTick = 0x378;
}

// not using this yet but leaving it here for later (entity stuff, ground check, etc)
// // PF flags
// constexpr uint32_t FL_ONGROUND = (1 << 0);
//
// // IN_* bits, same values as subtick_move enum
// constexpr uint32_t IN_JUMP     = (1 << 1); // 2
//
// // entity list resolve:
// //   list->m_pEntries[(handle & 0x7FFF) >> 9]  -> 16-entry page
// //   page entries are 0x78 bytes, ptr at +0x0.
// // layout doesn't seem to change across updates.
// inline void* GetEntityFromHandle(uintptr_t entityList, uint32_t handle) {
//     if (handle == UINT32_MAX || entityList == 0) return nullptr;
//
//     const uint32_t listIndex = (handle & 0x7FFF) >> 9;
//     const uintptr_t listChunk = *reinterpret_cast<uintptr_t*>(
//         entityList + 0x10 * listIndex + 0x8);
//     if (!listChunk) return nullptr;
//
//     return *reinterpret_cast<void**>(listChunk + 120 * (handle & 0x1FF));
// }
