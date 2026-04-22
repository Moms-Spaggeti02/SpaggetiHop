#pragma once
#include <cstdint>
#include <Windows.h>

// CS2 offsets. these break every update, pull fresh ones from a2x / offsets.hpp.
// everything is relative to client.dll unless i say otherwise.
namespace offsets {
    // client.dll
    constexpr uintptr_t dwEntityList       = 0x24CED50; // CGameEntitySystem*
    constexpr uintptr_t dwLocalPlayerPawn  = 0x20547A0; // CHandle<C_CSPlayerPawn>

    // C_BaseEntity netvars
    constexpr uintptr_t m_fFlags           = 0x3F8; // uint32
    constexpr uintptr_t m_vecVelocity      = 0x430; // CNetworkVelocityVector (first 12 bytes = Vector xyz)
    constexpr uintptr_t m_hGroundEntity    = 0x530; // CHandle (UINT32_MAX = not on ground)
    constexpr uint32_t  FL_ONGROUND        = 1 << 0;

    // C_CSPlayerPawn: real-time view angles for autostrafe.
    // m_angEyeAnglesVelocity[.y] gives per-tick yaw delta — positive = mouse
    // moved right, negative = left. threshold it to drive strafe direction.
    constexpr uintptr_t m_angEyeAngles         = 0x3300; // QAngle (pitch=[0], yaw=[1], roll=[2])
    constexpr uintptr_t m_angEyeAnglesVelocity = 0x33D0; // QAngle

    // C_CSPlayerPawn -> CPlayer_MovementServices*
    constexpr uintptr_t m_pMovementServices = 0x1220;

    // CPlayer_MovementServices: float[4] subtick "when" for forced button edges.
    // write 0.0 to get earliest-in-tick timing for the jump press, giving the
    // engine sub-tick precision on the bhop instead of whole-tick granularity.
    constexpr uintptr_t m_arrForceSubtickMoveWhen = 0x1B0;

    // CPlayer_MovementServices: input cmd move values. writing these pre-CreateMove
    // feeds the cmd builder our autostrafe values so the cmd ships with our
    // wishdir rather than what the keyboard reported.
    constexpr uintptr_t m_flMaxspeed       = 0x1AC; // float
    constexpr uintptr_t m_flCmdForwardMove = 0x1A0; // float (+ = W, - = S)
    constexpr uintptr_t m_flCmdLeftMove    = 0x1A4; // float (+ = D, - = A)
    constexpr uintptr_t m_flForwardMove    = 0x1C0; // float (physics-consumed)
    constexpr uintptr_t m_flLeftMove       = 0x1C4; // float (physics-consumed)

    // CCSPlayer_MovementServices (subclass) - stamina + last-jump tracking.
    // m_flStamina rises on jump, decays over time. high stamina = reduced jump
    // height AND m_flVelMulAtJumpStart dampened horizontal velocity preservation.
    // gate jumps on high stamina -> consistent max-height chain.
    constexpr uintptr_t m_flStamina            = 0x674; // float [0, ~100]
    constexpr uintptr_t m_nLastJumpTick        = 0x6E0; // GameTick_t (int32)
    constexpr uintptr_t m_flVelMulAtJumpStart  = 0x688; // float

    // jump button state the engine reads. dumper calls this buttons::jump now.
    // press = 0x10001, release = 0x100.
    constexpr uintptr_t dwForceJump        = 0x204DF30;

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
