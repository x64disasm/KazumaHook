# KazumaHook
A lightweight and minimal **trampoline hook** for **ARM64** devices.  
Designed as a clean alternative to third-party dependencies like **Dobby**.

## Usage
**NOTE:** RVA **must be rebased** before passing it to the hook

To rebase an address, calculate:
``base + RVA``
```cpp
#include "KazumaHook.h"

int64_t (*original_function)(int64_t) = nullptr;
int64_t detour_function(int64_t a1)
{
    return original_function(a1); // Trampoline call
}

bool is_hooked = KazumaHook(REBASE(0xFFFFFF), (void*)detour_function, (void**)&original_function);
if (is_hooked)
{
    printf("Successfully hooked");
}
else
{
    printf("Failed to hook");
}
