# SpaggetiHop

A tick-perfect bunnyhop for Counter-Strike 2.

Single-file loader — no manual injector, no external DLL to drop in. Launch `SpaggetiHop.exe`, start CS2, hold SPACE, and every jump lands on the frame the server expects.

> **⚠️ Launch `SpaggetiHop.exe` BEFORE `cs2.exe`.** The loader waits for CS2 and injects as it starts up — running it after CS2 is already open is unreliable.

## Features

- **Tick-synced jumps.** Toggles the jump state once per client tick, so there's no double-press, no skipped hop, no luck involved.
- **Self-contained.** The payload DLL is embedded as a resource inside the EXE; the loader extracts and injects it automatically.
- **Waits for the game.** Launch it before CS2 — it'll sit and inject the moment `cs2.exe` shows up (up to 5 minutes).
- **Clean unload.** Press END in-game and the hook is removed, trampolines are freed, and the DLL unloads itself. No game restart needed.
- **Light obfuscation.** Strings are XOR-encrypted at compile time, module/API resolution is done through PEB walks with FNV1a-hashed names — so none of the obvious giveaways (`client.dll`, `CreateMove`, etc.) appear as plain strings in the binary.

## Usage

1. Download `SpaggetiHop.exe`.
2. Run it **before launching CS2**.
3. Launch CS2. A console opens with a hot-pink banner — when the animation stops, you're injected.
4. In-game: hold **SPACE** to auto-hop.
5. Press **END** to unload.

## Controls

| Key   | Action           |
|-------|------------------|
| SPACE | Tick-synced hop  |
| END   | Unload the cheat |

## Troubleshooting

- **SPACE does nothing in-game** — CS2 likely got an update; the offsets in `SDK.h` are stale and need refreshing from a public dumper (a2x / offsets.hpp).
- **Console closes instantly** — check `bhop_error.log` next to the EXE; that's where startup errors get written.
- **Antivirus flags it** — expected. It's a DLL injector. Whitelist the EXE or pause real-time scanning before running.

## How it works (short version)

The EXE carries the DLL as an embedded resource, extracts it to `%TEMP%`, and injects it into `cs2.exe` via `LoadLibrary` in a remote thread. Once inside, the DLL pattern-scans `client.dll` for `CreateMove`, hooks it with MinHook, and toggles the engine's force-jump flag between PRESS and RELEASE on each new client tick — which is exactly what a pixel-perfect bunnyhop looks like to the server.

## Disclaimer

Use at your own risk. Intended for offline play and community servers. Don't use on VAC-protected matchmaking.
