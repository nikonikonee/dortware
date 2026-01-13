#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>



namespace utils
{


    DWORD getpid(const char* name);
    uintptr_t getmodulebase(DWORD pid, const char* mod);
    HMODULE getmodulehandle(DWORD pid, const char* moduleName);
    void clearc();
    void pausec();
    void load(int seconds);
    void closec();
    void detected(DWORD pid);
    bool scan();
    bool enablepriv();
    bool hdbp();
    void showcur();
    void hidecur();
    bool ttmodif();
    void initinteg();
    bool mmbp();
    DWORD hhbf(const BYTE* data, size_t size);
    bool iequals(const std::string& a, const std::string& b);
    DWORD WINAPI detect(LPVOID lpParam);
    void killproctree(DWORD pid);
    void rapeproc(DWORD pid);


    

    namespace logger
    {
        void logwarn(const char* text);
        void logerror(const char* text);
        void loginfo(const char* text);
        void loginfoin(const char* text);
        void loggood(const char* text);

        void logwarn(const char* text, uintptr_t value);
        void logerror(const char* text, uintptr_t value);
        void loginfo(const char* text, uintptr_t value);
        void loggood(const char* text, uintptr_t value);
    }
}
