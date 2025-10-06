//
// Created by x64disasm (Nathan) at 2025/06/10
//

#include "KazumaHook.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

namespace Kazuma {
    static inline size_t aU(size_t x, size_t a) {
        return (x + (a - 1)) & ~(a - 1);
    }

    static void fC(void* a, size_t l) {
        __builtin___clear_cache((char*)a, (char*)a + l);
    }

    static bool mP(void* a, size_t l, int p) {
        size_t ps = sysconf(_SC_PAGESIZE);
        uintptr_t s = (uintptr_t)a & ~(ps - 1);
        uintptr_t e = ((uintptr_t)a + l + ps - 1) & ~(ps - 1);
        return mprotect((void*)s, e - s, p) == 0;
    }

    static void* mX(size_t s) {
        s = aU(s, sysconf(_SC_PAGESIZE));
        void* p = mmap(nullptr, s, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
        return p == MAP_FAILED ? nullptr : p;
    }

    static size_t jA(void* b, uintptr_t t) {
        uint8_t* o = reinterpret_cast<uint8_t*>(b);
        uint32_t ldr = 0x58000000u | (2 << 5) | 17;
        uint32_t br  = 0xD61F0000u | (17 << 5);
        memcpy(o + 0, &ldr, 4);
        memcpy(o + 4, &br, 4);
        memcpy(o + 8, &t, 8);
        return 16;
    }

    static uintptr_t gB() {
        Dl_info i;
        if (!dladdr((void*)&gB, &i)) return 0;
        return (uintptr_t)i.dli_fbase;
    }

    static void* cT(void* t, void* n, size_t s) {
        s = aU(s, 4);
        if (s < 16) s = 16;

        void* tr = mX(s + 16);
        if (!tr) return nullptr;

        memcpy(tr, t, s);
        jA(reinterpret_cast<uint8_t*>(tr) + s, (uintptr_t)t + s);
        fC(tr, s + 16);

        if (!mP(t, s, PROT_READ | PROT_WRITE | PROT_EXEC)) {
            munmap(tr, aU(s + 16, sysconf(_SC_PAGESIZE)));
            return nullptr;
        }

        uint8_t p[32] = {0};
        jA(p, (uintptr_t)n);
        memcpy(t, p, 16);

        const uint32_t nop = 0xD503201Fu;
        for (size_t i = 16; i < s; i += 4)
            memcpy(reinterpret_cast<uint8_t*>(t) + i, &nop, 4);

        mP(t, s, PROT_READ | PROT_EXEC);
        fC(t, s);
        return tr;
    }

    bool KazumaHook(uint64_t relativeAddr, void* detour, void** original) {
        if (!h || !o) return false;

        uintptr_t base = gB();
        if (!base) return false;

        void* target = reinterpret_cast<void*>(base + r);
        void* tramp = cT(target, h, 16);
        if (!tramp) return false;

        *o = tramp;
        return true;
    }
} // namespace Kazuma

extern "C" bool KazumaHook(uint64_t relativeAddr, void* detour, void** original)
{
    return Kazuma::KazumaHook(relativeAddr, detour, original);
}