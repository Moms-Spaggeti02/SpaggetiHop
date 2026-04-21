#pragma once
#include <cstdint>
#include <cstddef>
#include <Windows.h>
#include <winternl.h>

// obf helpers. nothing fancy.
//   OBF("x")         xor'd at compile time, decrypted on the stack
//   obf::hash(...)   FNV1a, narrow or wide, lowercased
//   obf::mod(h)      find a loaded module by its hashed name (PEB walk)
//   obf::api(m, h)   same idea but for exports

namespace obf {

// FNV1a, lowercased, null terminated
constexpr uint32_t fnv_offset = 2166136261u;
constexpr uint32_t fnv_prime  = 16777619u;

constexpr char to_lower_c(char c) { return (c >= 'A' && c <= 'Z') ? char(c + 32) : c; }

constexpr uint32_t hash(const char* s) {
    uint32_t h = fnv_offset;
    while (*s) { h ^= uint8_t(to_lower_c(*s++)); h *= fnv_prime; }
    return h;
}
constexpr uint32_t hash(const wchar_t* s) {
    uint32_t h = fnv_offset;
    while (*s) {
        wchar_t c = *s++;
        if (c >= L'A' && c <= L'Z') c = wchar_t(c + 32);
        h ^= uint8_t(c);
        h *= fnv_prime;
    }
    return h;
}

// UNICODE_STRING version. BaseDllName in the PEB has a length, not a null
inline uint32_t hash_wide_n(const wchar_t* s, size_t n) {
    uint32_t h = fnv_offset;
    for (size_t i = 0; i < n; i++) {
        wchar_t c = s[i];
        if (!c) break;
        if (c >= L'A' && c <= L'Z') c = wchar_t(c + 32);
        h ^= uint8_t(c);
        h *= fnv_prime;
    }
    return h;
}

// compile-time xor'd string
constexpr uint8_t keybyte(uint32_t seed, size_t i) {
    uint32_t x = seed ^ (uint32_t(i) * 0x9E3779B9u);
    x ^= x >> 16; x *= 0x85EBCA6Bu;
    x ^= x >> 13; x *= 0xC2B2AE35u;
    x ^= x >> 16;
    return uint8_t(x);
}

template <size_t N, uint32_t SEED>
struct Encrypted {
    char data[N];
};

template <size_t N, uint32_t SEED>
constexpr Encrypted<N, SEED> encrypt_impl(const char (&s)[N]) {
    Encrypted<N, SEED> e{};
    for (size_t i = 0; i < N; ++i)
        e.data[i] = char(uint8_t(s[i]) ^ keybyte(SEED, i));
    return e;
}

template <size_t N>
struct Buffer {
    char buf[N];
    operator const char*() const { return buf; }
    const char* c_str() const { return buf; }
};

template <size_t N, uint32_t SEED>
__forceinline Buffer<N> decrypt(const Encrypted<N, SEED>& e) {
    // volatile read so LTCG/ICF doesn't just fold encrypt+decrypt back into
    // the original literal sitting in the caller.
    volatile uint32_t antiFold = SEED;
    uint32_t seed = antiFold;
    Buffer<N> out{};
    for (size_t i = 0; i < N; ++i)
        out.buf[i] = char(uint8_t(e.data[i]) ^ keybyte(seed, i));
    return out;
}

} // namespace obf

// __COUNTER__ so two OBFs on the same line still get different seeds.
#define OBF_SEED_()   (uint32_t(__LINE__) * 2654435761u ^ uint32_t(__COUNTER__) * 0x9E3779B1u ^ 0xDEADBEEFu)
#define OBF(s) ([]{                                                                                    \
    static constexpr uint32_t _oseed = OBF_SEED_();                                                    \
    static constexpr auto _oenc = ::obf::encrypt_impl<sizeof(s), _oseed>(s);                           \
    return ::obf::decrypt(_oenc);                                                                      \
}())

namespace obf {

// walk the PEB, find a module by its hashed name
inline HMODULE mod(uint32_t nameHash) {
#if defined(_M_X64)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (!peb || !peb->Ldr) return nullptr;

    auto* head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto* e = head->Flink; e != head; e = e->Flink) {
        // InMemoryOrderLinks is the 2nd LIST_ENTRY in the struct,
        // so step back one LIST_ENTRY to get to the real start.
        auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
            reinterpret_cast<uint8_t*>(e) - sizeof(LIST_ENTRY));
        if (!entry->DllBase) continue;
        size_t len = entry->FullDllName.Length / sizeof(wchar_t);
        const wchar_t* name = entry->FullDllName.Buffer;
        if (!name || !len) continue;
        // grab BaseDllName by finding the last '\\'
        const wchar_t* base = name;
        for (size_t i = 0; i < len; i++) if (name[i] == L'\\') base = name + i + 1;
        size_t baseLen = len - (base - name);
        if (hash_wide_n(base, baseLen) == nameHash)
            return reinterpret_cast<HMODULE>(entry->DllBase);
    }
    return nullptr;
}

// find an export by the hash of its name
inline FARPROC api(HMODULE m, uint32_t procHash) {
    if (!m) return nullptr;
    auto* base = reinterpret_cast<uint8_t*>(m);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& dir  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.Size) return nullptr;
    auto* exp   = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto* names = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
    auto* ords  = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = reinterpret_cast<const char*>(base + names[i]);
        if (hash(n) == procHash) {
            uint32_t rva = funcs[ords[i]];
            // forwarded export. RVA lands back inside the export dir,
            // it's a "MOD.Func" string, not an actual function. skip.
            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size)
                return nullptr;
            return reinterpret_cast<FARPROC>(base + rva);
        }
    }
    return nullptr;
}

} // namespace obf

// helper for inline API calls at the call site.
// usage:  API(kernel32, Sleep, VOID, (DWORD))(100);
#define API_FN(mod_hash, proc_hash, ret, args) \
    reinterpret_cast<ret(WINAPI*)args>(::obf::api(::obf::mod(mod_hash), proc_hash))
