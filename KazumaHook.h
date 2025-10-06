//
// Created by x64disasm (Nathan) at 2025/06/10
//

#pragma once

#include <cstdint>

namespace Kazuma {
    bool KazumaHook(uint64_t relativeAddr, void* detour, void** original);
}

// External wrapper for direct calls
extern "C" bool KazumaHook(uint64_t relativeAddr, void* detour, void** original);