#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120

#include <Windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <thread>
#include <Psapi.h>
#include <iostream>
#include <locale>
#include <codecvt>
#include <iomanip>
//#include "inireader.h"


//using namespace std;

bool isGenshin = 1;
bool _main_state = 1;
BYTE isAntimiss = 1;       
BYTE isHotpatch = 1;
//HWND _console_HWND = 0;
const BYTE _shellcode_genshin[48] = {0x83, 0xF9, 0x1E, 0x74, 0x16, 0x83, 0xF9, 0x2D, 0x74, 0x09, 0x90, 0xB9,
                                     0xFF, 0xFF, 0xFF, 0x7F, 0xEB, 0x10, 0xCC, 0xB9, 0x78, 0x00, 0x00, 0x00,
                                     0xEB, 0x08, 0xCC, 0xB9, 0x3C, 0x00, 0x00, 0x00, 0x66, 0x90, 0x89, 0x0D,
                                     0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};

//83 F9 1E                          cmp ecx,0x1E
//74 16                             je  --------------------------
//83 F9 2D                          cmp ecx,0x2D                 |
//74 09                             je  -----------------------  |
//90                                nop                       |  |
//B9 FF FF FF 7F                    mov ecx,0x7FFFFFFF        |  |
//EB 10                             jmp  label_write          |  |
//CC                                int3                      |  |
//B9 78 00 00 00                    mov ecx,0x78     <---------  |
//EB 08                             jmp  label_write             |
//CC                                int3                         |
//B9 3C 00 00 00                    mov ecx,0x3C       <----------
//label_write:
//66 90                             nop
//89 0D [00 00 00 00]               mov [rip+ [int] ],ecx
//C3                                ret
//CC CC CC CC CC CC CC              int3......
//

// 特征搜索 - 不是我写的 - 忘了在哪拷的
static uintptr_t PatternScan(void *module, const char *signature) {
    static auto pattern_to_byte = [](const char *pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char *>(pattern);
        auto end = const_cast<char *>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            } else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t *)module + dosHeader->e_lfanew);

    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t *>(module);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return (uintptr_t)&scanBytes[i];
        }
    }
    return 0;
}

static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char *signature) {
    auto pattern_to_byte = [](const char *pattern) {
        std::vector<int> bytes;
        const char *start = pattern;
        const char *end = pattern + strlen(pattern);

        for (const char *current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            } else {
                bytes.push_back(strtoul(current, const_cast<char **>(&current), 16));
            }
        }
        return bytes;
    };

    std::vector<int> patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t *>(startAddress);

    for (size_t i = 0; i < regionSize - patternBytes.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); ++j) {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return (uintptr_t)&scanBytes[i];
        }
    }
    return 0;
}

inline static std::wstring to_wide_string(const std::string &input) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(input);
}

// convert wstring to string
inline static std::string to_byte_string(const std::wstring &input) {
    // std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(input);
}

static std::string GetLastErrorAsString(DWORD code) {
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                   code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
    std::string ret = buf;
    LocalFree(buf);
    return ret;
}

// 获取目标进程DLL信息
static bool GetModule(DWORD pid, std::wstring ModuleName, PMODULEENTRY32 pEntry) {
    if (!pEntry)
        return false;

    MODULEENTRY32 mod32{};
    mod32.dwSize = sizeof(mod32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    bool temp = Module32First(snap, &mod32);
    if (temp) {
        do {
            if (mod32.th32ProcessID != pid) {
                break;
            }

            wchar_t temp[260];
            MultiByteToWideChar(CP_ACP, 0, mod32.szModule, -1, temp, 260);
            if (std::wstring(temp) == ModuleName) {
                *pEntry = mod32;
                CloseHandle(snap);
                return 1;
            } //This is for g++ compiler

	/*
            if (mod32.szModule == ModuleName) {
                *pEntry = mod32;
                CloseHandle(snap);
                return 1;
            }
	*/

        } while (Module32Next(snap, &mod32));
    }
    CloseHandle(snap);
    return 0;
}

// 通过进程名搜索进程ID
static DWORD GetPID(std::wstring ProcessName) {
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(snap, &pe32); Process32Next(snap, &pe32);) {

        wchar_t wExeFile[260];
        MultiByteToWideChar(CP_ACP, 0, pe32.szExeFile, -1, wExeFile, 260);
        if (std::wstring(wExeFile) == ProcessName) {
            pid = pe32.th32ProcessID;
            break;
        } //This is for g++ compiler
	
	/*
        if (std::wstring(pe32.szExeFile) == ProcessName) {
            pid = pe32.th32ProcessID;
            break;
        }
	*/
    }
    CloseHandle(snap);
    return pid;
}

// Hotpatch
static DWORD64 inject_patch(LPVOID unity_module, DWORD64 unity_baseaddr, DWORD64 _ptr_fps, HANDLE Tar_handle) {
    BYTE search_sec[] = ".text";                                                 // max 8 byte
    uintptr_t WinPEfileVA = *(uintptr_t *)(&unity_module) + 0x3c;                // dos_header
    uintptr_t PEfptr = *(uintptr_t *)(&unity_module) + *(uint32_t *)WinPEfileVA; // get_winPE_VA
    _IMAGE_NT_HEADERS64 _FilePE_Nt_header = *(_IMAGE_NT_HEADERS64 *)PEfptr;
    _IMAGE_SECTION_HEADER _sec_temp{};
    DWORD64 Module_TarSec_RVA;
    DWORD64 Module_TarSecEnd_RVA;
    DWORD Module_TarSec_Size;
    if (_FilePE_Nt_header.Signature == 0x00004550) {
        DWORD sec_num = _FilePE_Nt_header.FileHeader.NumberOfSections; // 获得指定节段参数
        DWORD num = sec_num;
        while (num) {
            _sec_temp =
                *(_IMAGE_SECTION_HEADER *)(PEfptr + 264 + (40 * (static_cast<unsigned long long>(sec_num) - num)));

            // printf_s("sec_%d_is:  %s\n", sec_num - num, _sec_temp.Name);
            int i = 8;
            int len = sizeof(search_sec) - 1;
            int cmp = 0;
            while ((i != 0) && _sec_temp.Name[8 - i] && search_sec[8 - i]) {
                if (_sec_temp.Name[8 - i] == search_sec[8 - i]) {
                    cmp++;
                }
                i--;
            }
            if (cmp == len) {
                Module_TarSec_RVA = _sec_temp.VirtualAddress + (DWORD64)unity_module;
                Module_TarSec_Size = _sec_temp.Misc.VirtualSize;
                Module_TarSecEnd_RVA = Module_TarSec_RVA + Module_TarSec_Size;
                goto __Get_target_sec;
            }
            num--;
        }
        //printf_s("Get Target Section Fail !\n");
        return 0;
    }
    return 0;

__Get_target_sec:
    DWORD64 address = 0;
    if (isGenshin) {
        DWORD64 Hook_addr = 0;
        DWORD64 Hook_addr_tar = 0;
        while (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size,
                                            "CC 89 0D ?? ?? ?? ?? C3 CC")) // 搜索正确patch点位
        {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t *)(rip) + 4;
            if ((rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) == _ptr_fps) {
                Hook_addr = address + 1;
                Hook_addr_tar = Hook_addr - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                goto __Get_Patch_addr;
            } else {
                *(uint64_t *)(address + 1) = 0xCCCCCCCCCCCCCCCC;
            }
        }
        //printf_s("\nPatch pattern outdate...\n");
        return 0;

    __Get_Patch_addr:
        uint32_t Qword_num = 0;
        uint64_t Patch_addr = 0;
        uint64_t Patch_addr_Tar = 0;
        while (*(uint64_t *)(Module_TarSecEnd_RVA + (Qword_num * 8)) == 0) // 获取区段尾部空余空间
        {
            Qword_num++;
            if (Qword_num == 9) {
                break;
            }
        }
        if (Qword_num >= 9) {
            // 先在buffer里Patch好，再写到TarProcess
            Patch_addr = ((Module_TarSecEnd_RVA + 32) >> 4) << 4; // 对齐
            *(uint64_t *)(Patch_addr - 8) = 0xCCCCCCCCCCCCCCCC;
            *(uint64_t *)(Patch_addr - 16) = 0xCCCCCCCCCCCCCCCC;
            Patch_addr_Tar = (Patch_addr - 16) - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
            { // copy shellcode
                uint64_t *temp_ptr = (uint64_t *)Patch_addr;
                uint64_t *temp_ptr_sc = (uint64_t *)&_shellcode_genshin;
                int32_t pa_offset = 0;
                int i = 0;
                while (i != 6) {
                    *(uint64_t *)(temp_ptr + i) = *(uint64_t *)(temp_ptr_sc + i);
                    i++;
                }
                *(uint32_t *)(Patch_addr + 0x14) = FPS_TARGET;
                uint64_t RVA_fps = (_ptr_fps - (uintptr_t)unity_baseaddr) + (uintptr_t)unity_module;
                *(uint32_t *)(Patch_addr + 0x24) = (uint32_t)(RVA_fps - (uint32_t)(Patch_addr + 0x28));
            }
            int32_t _jmp_im_num = Patch_addr - (Hook_addr + 5); // hook原来的set
            *(uint64_t *)Hook_addr = 0xCCCCCC00000000E9;
            *(uint32_t *)(Hook_addr + 1) = _jmp_im_num;
            //----------------------------------------------buffer_ok----------------------------------------------//
            if (WriteProcessMemory(Tar_handle, (LPVOID)Patch_addr_Tar, (LPVOID)(Patch_addr - 16), 0x40, 0) == 0) {
                DWORD ERR_code = GetLastError();
                //printf_s("\nWrite Target_Patch Fail! ( 0x%X ) - %s\n", ERR_code,
                //         GetLastErrorAsString(ERR_code).c_str());
                return 0;
            }
            if (WriteProcessMemory(Tar_handle, (LPVOID)Hook_addr_tar, (LPVOID)Hook_addr, 0x8, 0) == 0) {
                DWORD ERR_code = GetLastError();
                //printf_s("\nWrite Target_Hook Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                return 0;
            }
            return (Patch_addr_Tar + 0x24);
        }
        //printf_s("\nPatch Failed cause no enough space in module...\n");
        return 0;
    } else {
        while (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size,
                                            "CC 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC CC")) // 搜索正确patch点位
        {
            uintptr_t rip = address;
            rip += 3;
            int32_t eax_fps_of = *(int32_t *)(rip);
            if ((eax_fps_of >> 31) == 1) {
                eax_fps_of += 5;
            } else {
                eax_fps_of -= 5;
            }
            int32_t ebx_jmp_im = *(int32_t *)(rip + 5);
            if ((ebx_jmp_im >> 31) == 1) {
                ebx_jmp_im += 5;
            } else {
                ebx_jmp_im -= 5;
            }
            rip += *(int32_t *)(rip) + 4;
            if ((rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) == _ptr_fps) {
                DWORD64 Patch0_addr = address + 1;
                DWORD64 Patch0_addr_hook = Patch0_addr - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                *(int64_t *)Patch0_addr = 0x000D8900000078B9;
                *(int64_t *)(Patch0_addr + 8) = 0x00000000E9000000;
                *(int32_t *)(Patch0_addr + 1) = FPS_TARGET;
                *(int32_t *)(Patch0_addr + 7) = eax_fps_of;
                *(int32_t *)(Patch0_addr + 12) = ebx_jmp_im;
                if (WriteProcessMemory(Tar_handle, (LPVOID)Patch0_addr_hook, (LPVOID)Patch0_addr, 0x10, 0) == 0) {
                    DWORD ERR_code = GetLastError();
                    //printf_s("\nWrite Target_Patch Fail! ( 0x%X ) - %s\n", ERR_code,
                    //         GetLastErrorAsString(ERR_code).c_str());
                    return 0;
                }
                return ((address - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) + 2);
            }
            Module_TarSec_Size = address - Module_TarSec_RVA;
            Module_TarSec_RVA = address + 12;
        }
        //printf_s("\nPatch pattern outdate...\n");
        return 0;
    }
}

extern "C" __declspec(dllexport) int genshinLaunch(std::string GamePath, int FpsValue) {

    std::string CommandLine{};

__choose_ok:
    DWORD TargetFPS = FpsValue;
    std::string ProcessPath = GamePath;
    std::string ProcessDir{};

    //std::cout<< "GamePath: " << ProcessPath.c_str() << std::endl;
    //std::cout << "TargetFPS: " << TargetFPS << std::endl;

    if (ProcessPath.length() < 8)
        return 0;

    //cout << "GamePath: " << ProcessPath.c_str() << endl;
    ProcessDir = ProcessPath.substr(0, ProcessPath.find_last_of("\\"));
    std::wstring prcessname = to_wide_string(ProcessPath.substr(ProcessPath.find_last_of("\\") + 1));

_wait_process_close:
    DWORD pid = GetPID(prcessname);
    if (pid) {
        //int state =
        //    MessageBoxW(NULL,
        //                L"Game has being running! \n游戏已在运行！\nYou can click yes to auto close game and restart "
        //                L"or click cancel to manually close. \n点击确定自动关闭游戏或手动关闭游戏后点取消\n",
        //                L"Error", 0x11);
        //if (state == 1) {
        //    HANDLE tempHandle = OpenProcess(PROCESS_TERMINATE, false, pid);
        //    TerminateProcess(tempHandle, 0);
        //    CloseHandle(tempHandle);
        //    Sleep(2000);
        //    goto _wait_process_close;
        //}
        //printf_s("Now close this console and reboot unlocker.\n现在可以重启解锁器\n");
        //system("pause");
        return 0;
    }

    STARTUPINFOA si{};

    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(ProcessPath.c_str(), (LPSTR)CommandLine.c_str(), nullptr, nullptr, FALSE, 0, nullptr,
                        ProcessDir.c_str(), &si, &pi)) {
        DWORD ERR_code = GetLastError();
        //printf_s("\nCreateprocess Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        system("pause");
        return (int)-1;
    }

    CloseHandle(pi.hThread);
    //cout << "PID: " << pi.dwProcessId << endl;

    Sleep(500);
    // 等待UnityPlayer.dll加载和获取DLL信息
    MODULEENTRY32 hUnityPlayer{};

    {
        DWORD times = 1000;
        while (!GetModule(pi.dwProcessId, L"UnityPlayer.dll", &hUnityPlayer)) {
            Sleep(50);
            times -= 5;
            if (GetModule(pi.dwProcessId, L"unityplayer.dll", &hUnityPlayer)) {
                goto __get_unity_ok;
            }
            if (times == 0) {
                //cout << "Get unity module time out!" << endl;
                CloseHandle(pi.hProcess);
                system("pause");
                return (int)-1;
            }
        }
    }

__get_unity_ok:

    //cout << "UnityPlayer: 0x" << setiosflags(ios::uppercase) << hex << (uintptr_t)hUnityPlayer.modBaseAddr << endl;

    // 在本进程内申请UnityPlayer.dll大小的内存 - 用于特征搜索
    LPVOID up = VirtualAlloc(nullptr, hUnityPlayer.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!up) {
        DWORD ERR_code = GetLastError();
        //printf_s("\nVirtualAlloc failed! ( 0x%X ) - %s", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        system("pause");
        CloseHandle(pi.hProcess);
        return (int)-1;
    }
    if (hUnityPlayer.modBaseAddr == 0) {
        //printf_s("\nUnityPlayerBaseAddrptr is null ! \n");
        CloseHandle(pi.hProcess);
        system("pause");
        return (int)-1;
    }
    // 把整个模块读出来
    if (!ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, up, hUnityPlayer.modBaseSize, nullptr)) {
        DWORD ERR_code = GetLastError();
        //printf_s("\nRead UnityPlayer module Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        CloseHandle(pi.hProcess);
        VirtualFree(up, 0, MEM_RELEASE);
        system("pause");
        return (int)-1;
    }

    //printf_s("Searching for pattern...\n");
    //
    // starrail fps 66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0
    // Vsync 3B 15 ?? ?? ?? ?? 0F 84 86 00 00 00 48 89 74 24 40 40 84 FF
    //
    // 7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8
    //
    // 7F 0E E8 ? ? ? ? 66 0F 6E C8 0F 5B C9
    //
    // 计算相对地址 (FPS)

    // uintptr_t pVSync = 0;    //Game_Vsync_ptr
    // uintptr_t pVSync_fps = 0;//Game_Vsync_target_fps_ptr

    uintptr_t pfps = 0; // normal_fps_ptr
    DWORD64 address = 0;
    if (isGenshin) {
        address = PatternScan(up, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - last
        if (address) {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t *)(rip) + 6;
            rip += *(int32_t *)(rip) + 4;
            pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
            goto __offset_ok;
        }
        address = PatternScan(up, "7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8"); // ver old
        if (address) {
            uintptr_t rip = address;
            rip += 4;
            rip += *(int32_t *)(rip) + 4;
            pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
            goto __offset_ok;
        }
        //MessageBoxA(_console_HWND, "Genshin Pattern Outdated!\nPlase wait new update in github.\n\n", "Error", 0x10);
        CloseHandle(pi.hProcess);
        VirtualFree(up, 0, MEM_RELEASE);
        return (int)-1;

    } else {
        address = PatternScan(up, "66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0"); // ver 1.0 - last
        if (address) {
            uintptr_t rip = address;
            rip += 4;
            rip += *(int32_t *)(rip) + 4;
            pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
            goto __offset_ok;
        }
        //MessageBoxA(_console_HWND, "StarRail Pattern Outdated!\nPlase wait new update in github.\n\n", "Error", 0x10);
        CloseHandle(pi.hProcess);
        VirtualFree(up, 0, MEM_RELEASE);
        return (int)-1;
    }
    //-----------------------------------------------------------------------------------------------------------------//

__offset_ok:

    uintptr_t Patch_ptr;
    if (isHotpatch == 1) {
        Patch_ptr = inject_patch(up, (DWORD64)hUnityPlayer.modBaseAddr, pfps, pi.hProcess); // 45 patch config
        if (Patch_ptr == NULL) {
            //printf_s("Inject Patch Fail!\n\n");
        }
    }
    VirtualFree(up, 0, MEM_RELEASE);

    DWORD dwExitCode = STILL_ACTIVE;
    int32_t fps = 0; // game real
    while (1) {
        if (_main_state) {
            if ((ReadProcessMemory(pi.hProcess, (LPVOID)pfps, &fps, sizeof(fps), nullptr)) == NULL) {
                DWORD ERR_code = GetLastError();
                if (ERR_code == ERROR_ACCESS_DENIED && isHotpatch == 0) {
                    //printf_s("\nRead mem failed(0x5 ERROR_Access_Denied), May mem protect has load,try again with open "
                    //         "hotpatch\n权限拒绝(0x5)可能内存保护已经完全加载 可以尝试开启热修补 \n");
                } else {
                    //printf_s("\nRead Target_fps Fail! ( 0x%X ) - %s \n", ERR_code,
                    //         GetLastErrorAsString(ERR_code).c_str());
                }
                goto __exit_main;
            }
            if (fps != TargetFPS) {
                if ((WriteProcessMemory(pi.hProcess, (LPVOID)pfps, &TargetFPS, sizeof(TargetFPS), nullptr)) == NULL) {
                    DWORD ERR_code = GetLastError();
                    if (ERR_code == ERROR_ACCESS_DENIED && isHotpatch == 0) {
                        //printf_s("\nWrite mem failed(0x5 ERROR_Access_Denied), May mem protect has load,try again with "
                        //         "open hotpatch\n权限拒绝(0x5)可能内存保护已经完全加载 可以尝试开启热修补 \n");
                    } else {
                        //printf_s("\nWrite Target_fps Fail! ( 0x%X ) - %s \n", ERR_code,
                        //         GetLastErrorAsString(ERR_code).c_str());
                    }
                    goto __exit_main;
                }
                if (TargetFPS >= 120) {
                    SetPriorityClass(pi.hProcess, REALTIME_PRIORITY_CLASS);
                }
                if (TargetFPS <= 90 && TargetFPS >= 60) {
                    SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);
                }
                if (TargetFPS <= 60) {
                    SetPriorityClass(pi.hProcess, NORMAL_PRIORITY_CLASS);
                }
                if (TargetFPS <= 30) {
                    SetPriorityClass(pi.hProcess, BELOW_NORMAL_PRIORITY_CLASS);
                }
                if (isHotpatch && Patch_ptr) {
                    if ((WriteProcessMemory(pi.hProcess, (LPVOID)Patch_ptr, &TargetFPS, sizeof(TargetFPS), nullptr)) ==
                        NULL) {
                        DWORD ERR_code = GetLastError();
                        if (ERR_code == ERROR_ACCESS_DENIED) {
                            //printf_s("\nWrite failed(0x5 ERROR_Access_Denied), May mem protect has "
                            //         "load.\n权限拒绝(0x5)可能内存保护已经完全加载 \n");
                        }
                        goto __exit_main;
                    }
                }
            }
        }
        Sleep(500);
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        if (dwExitCode != STILL_ACTIVE) {
            //printf_s("\nGame Terminated !\n");
            break;
        }
    }

__exit_main:
    CloseHandle(pi.hProcess);
    //system("pause");
    return 1;
}
/*
int main(int argc, char **argv) {
    genshinLaunch("E:\\MiHoYo\\GenshinImpact\\YuanShen.exe", 144);
    //genshinLaunch("D:\\Genshin Impact\\Genshin Impact Game\\YuanShen.exe", 144);
    return 0;
}
*/