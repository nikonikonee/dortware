#pragma once
#include <Windows.h>
#include <cstdint>

/*
*
* /------------HOOKER.H------------\
* | Project made by niko           |
* | External hooker                |
* | All rights reserved 2025       |
* \------------HOOKER.H------------/
*
*/

namespace hooker
{
    struct hook_t
    {
        HANDLE hProcess;
        uintptr_t target;
        uintptr_t trampoline;
        uintptr_t stub;
        uint8_t original[12];
        size_t length;
    };

    bool hook(
        HANDLE hProcess,
        uintptr_t target,
        const void* stubBytes,
        size_t stubSize,
        hook_t& out
    );

    bool unhook(hook_t& hook);
}
