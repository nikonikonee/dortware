#include "utils.h"
#include "skCrypt.h"
#include <TlHelp32.h>
#include <iostream>
#include <Windows.h>
#include <thread>
#include <cstdint>
#include <fstream>
#include <shellapi.h>
#include <string>
#include <algorithm>
#include <winternl.h>


#ifdef _M_X64
PPEB peb = (PPEB)__readgsqword(0x60);
#else
PPEB peb = (PPEB)__readfsdword(0x30);
#endif


namespace utils
{

    bool enablepriv()
    {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hToken);

        return GetLastError() == ERROR_SUCCESS;
    }

    void killproctree(DWORD pid)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);

        if (Process32First(snap, &pe))
        {
            do
            {
                if (pe.th32ParentProcessID == pid)
                {
                    killproctree(pe.th32ProcessID);
                }
            } while (Process32Next(snap, &pe));
        }

        CloseHandle(snap);

        HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc)
        {
            TerminateProcess(hProc, 0xDEAD);
            CloseHandle(hProc);
        }
    }

    void rapeproc(DWORD pid)
    {
        enablepriv();

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
            return;


        TerminateProcess(hProcess, 0x1337);


        killproctree(pid);


        HANDLE hJob = CreateJobObjectA(nullptr, nullptr);
        if (hJob)
        {
            AssignProcessToJobObject(hJob, hProcess);
            TerminateJobObject(hJob, 1);
            CloseHandle(hJob);
        }

        CloseHandle(hProcess);
    }

    DWORD getpid(const char* name)
    {
        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(pe);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        if (Process32First(snap, &pe))
        {
            do
            {
                if (!_stricmp(pe.szExeFile, name))
                {
                    CloseHandle(snap);
                    return pe.th32ProcessID;
                }
            } while (Process32Next(snap, &pe));
        }

        CloseHandle(snap);
        return 0;
    }

    bool iequals(const std::string& a, const std::string& b)
    {
        return std::equal(a.begin(), a.end(),
            b.begin(), b.end(),
            [](char a, char b)
            {
                return tolower(a) == tolower(b);
            });
    }

    uintptr_t getmodulebase(DWORD pid, const char* mod)
    {
        MODULEENTRY32 me{};
        me.dwSize = sizeof(me);

        HANDLE snap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid
        );

        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        if (Module32First(snap, &me))
        {
            do
            {
                if (!_stricmp(me.szModule, mod))
                {
                    CloseHandle(snap);
                    return reinterpret_cast<uintptr_t>(me.modBaseAddr);
                }
            } while (Module32Next(snap, &me));
        }

        CloseHandle(snap);
        return 0;
    }

    HMODULE getmodulehandle(DWORD pid, const char* moduleName)
    {
        MODULEENTRY32 me{};
        me.dwSize = sizeof(me);

        HANDLE snap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid
        );

        if (snap == INVALID_HANDLE_VALUE)
            return nullptr;

        if (Module32First(snap, &me))
        {
            do
            {
                if (!_stricmp(me.szModule, moduleName))
                {
                    CloseHandle(snap);
                    return reinterpret_cast<HMODULE>(me.modBaseAddr);
                }
            } while (Module32Next(snap, &me));
        }

        CloseHandle(snap);
        return nullptr;
    }


    void clearc()
    {
        system(skCrypt("cls").decrypt());
    }

    void pausec()
    {
        system(skCrypt("pause").decrypt());
    }

    void load(int seconds)
    {
        const char spinner[] = { '|', '/', '-', '\\' };
        const int spincount = 4;

        int ticks = seconds * 10;
        int index = 0;

        for (int i = 0; i < ticks; i++)
        {
            std::cout << skCrypt("\r[").decrypt() << spinner[index] << skCrypt("]").decrypt() << std::flush;
            index = (index + 1) % spincount;
            Sleep(100);
        }

        std::cout << skCrypt("\n").decrypt();
    }

    void closec()
    {
        HANDLE hProcess = GetCurrentProcess();
        TerminateProcess(hProcess, 0xBEEF);

    }

    void detected(DWORD pid)
    {
        rapeproc(pid);

    }

    bool scan()
    {
        bool found = false;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);

        if (Process32First(snapshot, &pe))
        {
            do
            {

                if (iequals(pe.szExeFile, skCrypt("ollydbg.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ida.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ida64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idag.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idag64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idaw.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idaw64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idaq.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idaq64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idau.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("idau64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("x64dbg.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("x32dbg.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("x64dbg-unsigned.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("x32dbg-unsigned.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("windbg.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("dbgview.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("dbgview64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("vsdebugeng.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("vsjitdebugger.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("scylla.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("scylla_x64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("scylla_x86.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("protection_id.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ImportREC.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("KdDumper.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ExtremeDumper.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ProcessDump.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("PETools.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("reshacker.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ResourceHacker.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("Hacker.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("LordPE.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("PEiD.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("CFF Explorer.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("cheatengine.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("cheatengine-x86_64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ProcessHacker.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ProcessHacker2.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ProcessExplorer.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("procexp.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("procexp64.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("tcpview.exe").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("IMMUNITYDEBUGGER.EXE").decrypt()) ||
                    iequals(pe.szExeFile, skCrypt("ExtremeInjector.exe").decrypt()))
                {
                    detected(pe.th32ProcessID);
                    found = true;
                }

            } while (Process32Next(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return found;
    }

    bool hdbp() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
        }
        return false;
    }


    bool mmbp() {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery((LPCVOID)mmbp, &mbi, sizeof(mbi));
        return !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
    }



    DWORD hhbf(const BYTE* data, size_t size)
    {
        DWORD hash = 5381;
        for (size_t i = 0; i < size; i++)
            hash = ((hash << 5) + hash) + data[i];
        return hash;
    }

    DWORD g_TextHash = 0;
    const char* text = skCrypt(".text").decrypt();

    void initinteg()
    {
        HMODULE mod = GetModuleHandle(nullptr);
        auto dos = (IMAGE_DOS_HEADER*)mod;
        auto nt = (IMAGE_NT_HEADERS*)((BYTE*)mod + dos->e_lfanew);

        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (!memcmp(sec->Name, text, 5))
            {
                BYTE* textBase = (BYTE*)mod + sec->VirtualAddress;
                g_TextHash = hhbf(textBase, sec->Misc.VirtualSize);
                break;
            }
        }
    }

    bool ttmodif()
    {
        HMODULE mod = GetModuleHandle(nullptr);
        auto dos = (IMAGE_DOS_HEADER*)mod;
        auto nt = (IMAGE_NT_HEADERS*)((BYTE*)mod + dos->e_lfanew);

        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (!memcmp(sec->Name, text, 5))
            {
                BYTE* textBase = (BYTE*)mod + sec->VirtualAddress;
                return hhbf(textBase, sec->Misc.VirtualSize) != g_TextHash;
            }
        }
        return false;
    }



    DWORD WINAPI detect(LPVOID lpParam)
    {
        while (1)
        {


            if (ttmodif())
            {
                closec(); // .text section modified
            }
            
            if (scan())
            {
                closec();
            }

            if (IsDebuggerPresent())
            {
                closec();
            }

            BOOL isDebugged = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
            if (isDebugged)
            {
                closec();
            }


            if (peb->BeingDebugged)
            {
                closec();
            }

            Sleep(100);
        }
        return 0;
    }

    void showcur()
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_CURSOR_INFO cursorInfo;
        GetConsoleCursorInfo(hConsole, &cursorInfo);
        cursorInfo.bVisible = true;
        SetConsoleCursorInfo(hConsole, &cursorInfo);
    }

    void hidecur()
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_CURSOR_INFO cursorInfo;
        GetConsoleCursorInfo(hConsole, &cursorInfo);
        cursorInfo.bVisible = false;
        SetConsoleCursorInfo(hConsole, &cursorInfo);
    }


    namespace logger
    {
        static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        static void setc(WORD color)
        {
            SetConsoleTextAttribute(hConsole, color);
        }

        static void reset_color()
        {
            setc(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        void logerror(const char* text)
        {
            setc(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[-] ").decrypt() << text << std::endl;
            reset_color();
        }

        void logwarn(const char* text)
        {
            setc(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[!] ").decrypt() << text << std::endl;
            reset_color();
        }

        void loginfo(const char* text)
        {
            setc(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[*] ").decrypt() << text << std::endl;
            reset_color();
        }

        void loginfoin(const char* text)
        {
            setc(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[*] ").decrypt() << text;
            reset_color();
        }


        void loggood(const char* text)
        {
            setc(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[+] ").decrypt() << text << std::endl;
            reset_color();
        }

        void logerror(const char* text, uintptr_t value)
        {
            setc(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[-] ").decrypt() << text << skCrypt(" @ 0x").decrypt()
                << std::hex << value << std::dec << std::endl;
            reset_color();
        }

        void logwarn(const char* text, uintptr_t value)
        {
            setc(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[!] ").decrypt() << text << skCrypt(" @ 0x").decrypt()
                << std::hex << value << std::dec << std::endl;
            reset_color();
        }

        void loginfo(const char* text, uintptr_t value)
        {
            setc(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[*] ").decrypt() << text << skCrypt(" @ 0x").decrypt()
                << std::hex << value << std::dec << std::endl;
            reset_color();
        }

        void loggood(const char* text, uintptr_t value)
        {
            setc(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << skCrypt("[+] ").decrypt() << text << skCrypt(" @ 0x").decrypt()
                << std::hex << value << std::dec << std::endl;
            reset_color();
        }


    }
}

