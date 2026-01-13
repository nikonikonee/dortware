#include "in.h"

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
void sessionStatus();

using namespace KeyAuth;

std::string name = skCrypt("").decrypt();
std::string ownerid = skCrypt("").decrypt();
std::string version = skCrypt("").decrypt();
std::string url = skCrypt("").decrypt();
std::string path = skCrypt("").decrypt();

api KeyAuthApp(name, ownerid, version, url, path);


/* shitty gpt code but i could not care less it works */
bool g_RefereeSuspended = false;
bool SuspendRefereeThreads_External(HANDLE hProcess, DWORD pid, uintptr_t remoteRefereeBase) {
    if (g_RefereeSuspended || !remoteRefereeBase) return g_RefereeSuspended;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{ sizeof(te) };
    int suspended = 0;

    if (Thread32First(hSnap, &te)) {
        do {

            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    uintptr_t startAddr = 0;

                    typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(HANDLE, int, PVOID, ULONG, PULONG);
                    static auto NtQIT = (pfnNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

                    if (NtQIT) {
                        NTSTATUS status = NtQIT(hThread, 9, &startAddr, sizeof(startAddr), nullptr);


                        if (status >= 0 && startAddr >= remoteRefereeBase && startAddr < remoteRefereeBase + 0x5000000) {
                            if (SuspendThread(hThread) != (DWORD)-1) suspended++;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    g_RefereeSuspended = (suspended > 0);
    return g_RefereeSuspended;
}

int main()
{
    utils::initinteg();

    HANDLE hDetect = CreateThread(nullptr, 0, utils::detect, nullptr, 0, nullptr);
    if (!hDetect)
    {
        utils::closec();
    }
    else
    {
        CloseHandle(hDetect);
    }

    SetConsoleTitleA(skCrypt("@Dortware"));
    utils::hidecur();
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::string er = std::string(skCrypt("error ").decrypt()) + KeyAuthApp.response.message;
        utils::logger::logerror(er.c_str());
        utils::load(3);
        utils::closec();
    }

    utils::load(3);
    utils::clearc();

    std::string key;
    if (std::filesystem::exists("login.json"))
    {
        key = ReadFromJson("login.json", "license");
        KeyAuthApp.license(key);
    }
    else
    {
        utils::showcur();
        utils::logger::loginfoin(skCrypt("enter key "));
        std::cin >> key;
        KeyAuthApp.license(key);
    }

    if (!KeyAuthApp.response.success)
    {
        std::string er = std::string(skCrypt("error ").decrypt()) + KeyAuthApp.response.message;
        utils::logger::logerror(er.c_str());
        std::remove("login.json");
        Sleep(1500);
        exit(1);
    }

    utils::hidecur();
    WriteToJson("login.json", "license", key, false, "", "");


    std::thread run(checkauth, ownerid);
    std::thread check(sessionStatus);

    if (KeyAuthApp.user_data.username.empty()) exit(10);

    utils::clearc();
    utils::load(2);
    utils::clearc();





    utils::logger::loginfo(skCrypt("waiting for rec room"));

    DWORD pid{};
    while (!(pid = utils::getpid(skCrypt("RecRoom.exe"))))
        Sleep(500);

    utils::clearc();
    utils::load(3);
    utils::clearc();
    utils::logger::loggood(skCrypt("rec room found"));
    utils::load(1);
    utils::clearc();

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return 0;

    uintptr_t rf = utils::getmodulebase(pid, skCrypt("Referee.dll"));
    uintptr_t ga = utils::getmodulebase(pid, skCrypt("GameAssembly.dll"));

    if (!rf || !ga)
    {
        utils::clearc();
        if (!rf) utils::logger::logerror(skCrypt("could not find referee, try restarting your pc"));
        if (!ga) utils::logger::logerror(skCrypt("could not find gameassembly, try restarting your pc"));
        utils::load(3);
        return 0;
    }

    utils::logger::loggood(skCrypt("Referee.dll"), rf);
    utils::logger::loggood(skCrypt("GameAssembly.dll"), ga);
    utils::load(2);
    utils::clearc();

    HMODULE referee = utils::getmodulehandle(pid, skCrypt("Referee.dll"));

    SuspendRefereeThreads_External(hProc, pid, rf);
    
    utils::logger::loggood(skCrypt("referee disabled"));
    utils::load(2);
    utils::clearc();

    utils::logger::loginfo(skCrypt("press 1 to enable fly"));
    utils::logger::loginfo(skCrypt("press 2 to no gun cooldown"));
    utils::logger::loginfo(skCrypt("press 3 to toggle developer mode"));
    utils::logger::loginfo(skCrypt("press 4 to toggle inventory unlocker (unlock consumables, streaming camera, clothing customizer, share camera, room keys)"));
    utils::logger::loginfo(skCrypt("press 5 to toggle clothing unlocker (tiral ittems)"));
    utils::logger::loginfo(skCrypt("press 6 to toggle ssl"));


    while (true)
    {
        
        if (GetAsyncKeyState('1') & 1)  // 1 toggles flying
        {
            globals::movement::flying = !globals::movement::flying;
            utils::logger::loggood(skCrypt("flying"));
        }



        if (GetAsyncKeyState('2') & 1)  // 2 toggles nocooldown
        {
            globals::combat::nocooldown = !globals::combat::nocooldown;
            utils::logger::loggood(skCrypt("no cooldown"));
        }

        if (GetAsyncKeyState('3') & 1)  // 3 toggles developer mode
        {
            globals::player::developer = !globals::player::developer;
            utils::logger::loggood(skCrypt("developer mode"));
        }


        if (GetAsyncKeyState('4') & 1)  // 4 toggles inventory unlocker
        {
            globals::inventory::unlocker = !globals::inventory::unlocker;
            utils::logger::loggood(skCrypt("inventory unlocker"));
        }


        if (GetAsyncKeyState('5') & 1)  // 5 toggles clothing unlocker
        {
            globals::inventory::clothing = !globals::inventory::clothing;
            utils::logger::loggood(skCrypt("clothing"));
        }


        if (GetAsyncKeyState('6') & 1)  // 5 toggles ssl
        {
            globals::game::ssl = !globals::game::ssl;
            utils::logger::loggood(skCrypt("ssl"));
        }




        if (globals::combat::nocooldown)
        {
            hooker::hook(hProc, ga + offsets::combat::get_isoncooldown, globals::combat::nocooldown ? retts : retfs, globals::combat::nocooldown ? sizeof(retts) : sizeof(retfs), nc);

        }

        if (globals::player::developer)
        {
            hooker::hook(hProc, ga + offsets::player::get_isdeveloper, retts, sizeof(retts), dv);

        }
        else
        {
            hooker::hook(hProc, ga + offsets::player::get_isdeveloper, retfs, sizeof(retfs), dv);

        }

        if (globals::movement::flying)
        {
            hooker::hook(hProc, ga + offsets::movement::get_isflyingenabled, globals::movement::flying ? retts : retfs, globals::movement::flying ? sizeof(retts) : sizeof(retfs), fly);

        }

        if (globals::inventory::unlocker)
        {
            hooker::hook(hProc, ga + offsets::inventory::get_canuseconsumables, globals::inventory::unlocker ? retts : retfs, globals::inventory::unlocker ? sizeof(retts) : sizeof(retfs), v1);
            hooker::hook(hProc, ga + offsets::inventory::get_canusestreamcam, globals::inventory::unlocker ? retts : retfs, globals::inventory::unlocker ? sizeof(retts) : sizeof(retfs), v2);
            hooker::hook(hProc, ga + offsets::inventory::get_canusestreamingcamera, globals::inventory::unlocker ? retts : retfs, globals::inventory::unlocker ? sizeof(retts) : sizeof(retfs), v3);
            hooker::hook(hProc, ga + offsets::inventory::get_canuseclothingcustomizer, globals::inventory::unlocker ? retts : retfs, globals::inventory::unlocker ? sizeof(retts) : sizeof(retfs), v4);
            hooker::hook(hProc, ga + offsets::inventory::get_canusesharecamera, globals::inventory::unlocker ? retts : retfs, globals::inventory::unlocker ? sizeof(retts) : sizeof(retfs), v5);
            hooker::hook(hProc, ga + offsets::inventory::doeslocalplayerownkey1, globals::inventory::unlocker ? retts : retfs, globals::inventory::unlocker ? sizeof(retts) : sizeof(retfs), v6);
            hooker::hook(hProc, ga + offsets::inventory::doeslocalplayerownkey2, globals::inventory::unlocker ? retts : retfs, globals::inventory::unlocker ? sizeof(retts) : sizeof(retfs), v7);

        }

        if (globals::inventory::clothing)
        {
            hooker::hook(hProc, ga + offsets::clothing::get_isitemunlockedloccaly, globals::inventory::clothing ? retts : retfs, globals::inventory::clothing ? sizeof(retts) : sizeof(retfs), c1);
            hooker::hook(hProc, ga + offsets::clothing::get_isavataritemunlocked, globals::inventory::clothing ? retts : retfs, globals::inventory::clothing ? sizeof(retts) : sizeof(retfs), c2);
            hooker::hook(hProc, ga + offsets::clothing::isavataritemunlocked, globals::inventory::clothing ? retts : retfs, globals::inventory::clothing ? sizeof(retts) : sizeof(retfs), c3);
            hooker::hook(hProc, ga + offsets::clothing::get_isavataritemalredypurchased, globals::inventory::clothing ? retts : retfs, globals::inventory::clothing ? sizeof(retts) : sizeof(retfs), c4);
            hooker::hook(hProc, ga + offsets::clothing::isavataritemalredypurchased, globals::inventory::clothing ? retts : retfs, globals::inventory::clothing ? sizeof(retts) : sizeof(retfs), c5);

        }

        if (globals::game::ssl)
        {
            hooker::hook(hProc, ga + offsets::game::notifyservercert, globals::game::ssl ? nops : nops, globals::game::ssl ? sizeof(nops) : sizeof(nops), ssl);

        }

        Sleep(10);
    }

    return 0;
}

void sessionStatus() {
    KeyAuthApp.check(true);
    if (!KeyAuthApp.response.success) exit(0);

    if (KeyAuthApp.response.isPaid)
    {
        while (true)
        {
            Sleep(20000);
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) exit(0);
        }
    }
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10);
    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;
    localtime_s(&context, &timestamp);
    return context;
}

