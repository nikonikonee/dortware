#include "hooker.h"
#include "..\..\in.h"
#include <cstring>

/*
* 
* /------------HOOKER.CPP------------\
* | Project made by niko             |
* | External hooker                  |
* | All rights reserved 2025         |
* \------------HOOKER.CPP------------/ 
* 
*/

namespace hooker
{
    constexpr size_t HOOK_LEN = 12;

    static bool wrjmp(HANDLE hProc, uintptr_t src, uintptr_t dst)
    {
        uint8_t jmp[12] =
        {
            0x48, 0xB8,
            0,0,0,0,0,0,0,0,
            0xFF, 0xE0
        };

        memcpy(&jmp[2], &dst, sizeof(uintptr_t));

        SIZE_T written{};
        return WriteProcessMemory(hProc, (LPVOID)src, jmp, sizeof(jmp), &written)
            && written == sizeof(jmp);
    }

    bool hook(
        HANDLE hProcess,
        uintptr_t target,
        const void* stubBytes,
        size_t stubSize,
        hook_t& out
    )
    {
        out.hProcess = hProcess;
        out.target = target;
        out.length = HOOK_LEN;

        SIZE_T read{};
        if (!ReadProcessMemory(hProcess, (LPCVOID)target, out.original, HOOK_LEN, &read) || read != HOOK_LEN)
            return false;

        LPVOID remoteStub = VirtualAllocEx(hProcess, nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteStub)
            return false;

        SIZE_T written{};
        if (!WriteProcessMemory(hProcess, remoteStub, stubBytes, stubSize, &written) || written != stubSize)
            return false;

        uintptr_t trampoline = (uintptr_t)VirtualAllocEx(
            hProcess,
            nullptr,
            HOOK_LEN + 12,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!trampoline)
            return false;

        WriteProcessMemory(hProcess, (LPVOID)trampoline, out.original, HOOK_LEN, nullptr);
        wrjmp(hProcess, trampoline + HOOK_LEN, target + HOOK_LEN);
        wrjmp(hProcess, target, (uintptr_t)remoteStub);

        out.trampoline = trampoline;
        out.stub = (uintptr_t)remoteStub;

        return true;
    }

    bool unhook(hook_t& hook)
    {
        DWORD old{};
        VirtualProtectEx(hook.hProcess, (LPVOID)hook.target, hook.length, PAGE_EXECUTE_READWRITE, &old);

        SIZE_T written{};
        bool ok = WriteProcessMemory(
            hook.hProcess,
            (LPVOID)hook.target,
            hook.original,
            hook.length,
            &written
        ) && written == hook.length;

        VirtualProtectEx(hook.hProcess, (LPVOID)hook.target, hook.length, old, &old);

        return ok;
    }
}

