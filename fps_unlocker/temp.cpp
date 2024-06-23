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
#include "inireader.h"


using namespace std;

std::string HKSRGamePath{};
std::string GenGamePath{};
std::string GamePath{};
int32_t FpsValue = FPS_TARGET;
bool isGenshin = 1;
bool _main_state = 1;
bool Process_endstate = 0; // if set true will be quit
BYTE isAntimiss = 2; //no set state
BYTE isHotpatch = 2;
HWND _console_HWND = 0;
const BYTE _shellcode_genshin[48] = {0x83,0xF9,0x1E,
                               0x74,0x16,
                               0x83,0xF9,0x2D,
                               0x74,0x09,
                               0x90,
                               0xB9,0xFF,0xFF,0xFF,0x7F,
                               0xEB,0x10,
                               0xCC,
                               0xB9,0x78,0x00,0x00,0x00,
                               0xEB,0x08,
                               0xCC,
                               0xB9,0x3C,0x00,0x00,0x00,
                               0x66,0x90,
                               0x89,0x0D,0x00,0x00,0x00,0x00,
                               0xC3,
                               0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC};

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
static uintptr_t PatternScan(void* module, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

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

static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    auto pattern_to_byte = [](const char* pattern)
        {
            std::vector<int> bytes;
            const char* start = pattern;
            const char* end = pattern + strlen(pattern);

            for (const char* current = start; current < end; ++current) {
                if (*current == '?') {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else {
                    bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
                }
            }
            return bytes;
        };

    std::vector<int> patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(startAddress);

    for (size_t i = 0; i < regionSize - patternBytes.size(); ++i)
    {
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

inline static std::wstring to_wide_string(const std::string& input)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(input);
}
// convert wstring to string 
inline static std::string to_byte_string(const std::wstring& input)
{
    //std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(input);
}

static std::string GetLastErrorAsString(DWORD code)
{
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
    std::string ret = buf;
    LocalFree(buf);
    return ret;
}

// 获取目标进程DLL信息
static bool GetModule(DWORD pid, std::wstring ModuleName, PMODULEENTRY32 pEntry)
{
    if (!pEntry)
        return false;

    MODULEENTRY32 mod32{};
    mod32.dwSize = sizeof(mod32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    bool temp = Module32First(snap, &mod32);
    if (temp)
    {
        do
        {
            if (mod32.th32ProcessID != pid)
            {
                break;
            }
            if (mod32.szModule == ModuleName)
            {
                *pEntry = mod32;
                CloseHandle(snap);
                return 1;
            }

        } while (Module32Next(snap, &mod32));

    }
    CloseHandle(snap);
    return 0;
}

// 通过进程名搜索进程ID
static DWORD GetPID(std::wstring ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(snap, &pe32); Process32Next(snap, &pe32);)
    {
        if (pe32.szExeFile == ProcessName)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

static bool WriteConfig(int fps)
{
    HANDLE hFile = CreateFileA("hoyofps_config.ini", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD ERR_code = GetLastError();
        printf_s("\nCreateFileA failed!  ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        system("pause");
        return false;
    }

    std::string content{};
    content = "[Setting]\n";
    content += "GenshinPath=" + GenGamePath + "\n";
    content += "HKSRPath=" + HKSRGamePath + "\n";
    content += "IsAntiMisscontact=" + std::to_string(isAntimiss) + "\n";
    content += "IsHotpatch=" + std::to_string(isHotpatch) + "\n";
    content += "FPS=" + std::to_string(fps);


    DWORD written = 0;
    WriteFile(hFile, content.data(), content.size(), &written, nullptr);
    CloseHandle(hFile);
    return 1;
}

static bool LoadConfig()
{
    if (GetFileAttributesA("hoyofps_config") != INVALID_FILE_ATTRIBUTES)
        DeleteFileA("hoyofps_config");

    INIReader reader("hoyofps_config.ini");
    if (reader.ParseError() != 0)
    {
        cout << " Config Not Found !\n 配置文件未发现\n Don't close unlocker and open the game \n 不要关闭解锁器,并打开游戏\n Wait for game start ......\n 等待游戏启动.....\n" << endl;

_no_config:
        DWORD pid = 0;
        while (1)
        {
            if (isGenshin)
            {
                if ((pid = GetPID(L"YuanShen.exe")) || (pid = GetPID(L"GenshinImpact.exe")))
                {
                    break;
                }
            }
            else 
            {
                if (pid = GetPID(L"StarRail.exe"))
                {
                    break;
                }
            }
            Sleep(500);
        }
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess)
        {
            DWORD ERR_code = GetLastError();
            printf_s("\nOpenProcess failed! ( 0x%X ) - %s \n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
            system("pause");
            return 0;
        }

        // 获取进程句柄 - 这权限很低的了 - 不应该获取不了
        // PROCESS_QUERY_LIMITED_INFORMATION - 用于查询进程路经 (K32GetModuleFileNameExA)
        // SYNCHRONIZE - 用于等待进程结束 (WaitForSingleObject)
        
        char szPath[MAX_PATH]{};
        DWORD length = sizeof(szPath);
        QueryFullProcessImageNameA(hProcess, 0, szPath, &length);

        if (isGenshin) 
        {
            GenGamePath = szPath;
        }
        else 
        {
            HKSRGamePath = szPath;
        }
        GamePath = szPath;
        
        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE)
        {
            TerminateProcess(hProcess, 0);
            Sleep(500);
            GetExitCodeProcess(hProcess, &ExitCode);
        }

        // wait for the game to close then continue
        WaitForSingleObject(hProcess, -1);
        CloseHandle(hProcess);
        system("cls");
        goto __path_ok;
    }
    HKSRGamePath = reader.Get("Setting", "HKSRPath", "");
    GenGamePath = reader.Get("Setting", "GenshinPath", "");
    if (isGenshin)
    {
        GamePath = GenGamePath;
        if (GetFileAttributesA(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            printf_s(" Genshin Path Error!\n Plase open Genshin to set game path.\n 路径错误，请手动打开原神来设置游戏路径 \n");
            if (GetFileAttributesA(HKSRGamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                DeleteFileA("hoyofps_config.ini");
            }
            goto _no_config;
        }
    }
    else
    {
        GamePath = HKSRGamePath;
        if (GetFileAttributesA(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            printf_s(" HKSR Path Error!\n Plase open StarRail to set game path.\n 路径错误，请手动打开崩铁来设置游戏路径 \n");
            if (GetFileAttributesA(GenGamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                DeleteFileA("hoyofps_config.ini");
            }
            goto _no_config;
        }   
    }

__path_ok:
    isAntimiss = reader.GetInteger("Setting", "IsAntiMisscontact", 2);
    if (isAntimiss == 2)
    {
        int _msgbox_set = MessageBoxW(_console_HWND, L"Is set Anti-miscontact(Console window must be selected to set Fps) ? \n 是否开启防误触(只有选中解锁器窗口才可调节帧率)\n\n", L"Setting", 0x24);
        if (_msgbox_set == 6)
        {
            isAntimiss = 1;
        }
        if (_msgbox_set == 7)
        {
            isAntimiss = 0;
        }
    }
    isHotpatch = reader.GetInteger("Setting", "isHotpatch", 2);
    if (isHotpatch == 2)
    {
        int _msgbox_set = MessageBoxW(_console_HWND, L"Is enable Hotpatch (close unlocker will keep three gear option in game setting when patch success) ?\n 是否开启热修补(修补完成后可退出解锁器且保留三档帧率)\n\n", L"Setting", 0x24);
        if (_msgbox_set == 6)
        {
            isHotpatch = 1;
        }
        if (_msgbox_set == 7)
        {
            isHotpatch = 0;
        }
    }
    FpsValue = reader.GetInteger("Setting", "FPS", FPS_TARGET);
    WriteConfig(FpsValue);
    
    return 1;
}

//Hotpatch
static DWORD64 inject_patch(LPVOID unity_module, DWORD64 unity_baseaddr, DWORD64 _ptr_fps,HANDLE Tar_handle)
{
    BYTE search_sec[] = ".text";//max 8 byte
    uintptr_t WinPEfileVA = *(uintptr_t*)(&unity_module) + 0x3c; //dos_header
    uintptr_t PEfptr = *(uintptr_t*)(&unity_module) + *(uint32_t*)WinPEfileVA; //get_winPE_VA
    _IMAGE_NT_HEADERS64 _FilePE_Nt_header = *(_IMAGE_NT_HEADERS64*)PEfptr;
    _IMAGE_SECTION_HEADER _sec_temp{};
    DWORD64 Module_TarSec_RVA;
    DWORD64 Module_TarSecEnd_RVA;
    DWORD Module_TarSec_Size;
    if (_FilePE_Nt_header.Signature == 0x00004550)
    {
        DWORD sec_num = _FilePE_Nt_header.FileHeader.NumberOfSections;//获得指定节段参数
        DWORD num = sec_num;
        while (num)
        {
            _sec_temp = *(_IMAGE_SECTION_HEADER*)(PEfptr + 264 + (40 * (static_cast<unsigned long long>(sec_num) - num)));

            //printf_s("sec_%d_is:  %s\n", sec_num - num, _sec_temp.Name);
            int i = 8;
            int len = sizeof(search_sec) - 1;
            int cmp = 0;
            while ((i != 0) && _sec_temp.Name[8 - i] && search_sec[8 - i])
            {
                if (_sec_temp.Name[8 - i] == search_sec[8 - i])
                {
                    cmp++;
                }
                i--;
            }
            if (cmp == len)
            {
                Module_TarSec_RVA = _sec_temp.VirtualAddress + (DWORD64)unity_module;
                Module_TarSec_Size = _sec_temp.Misc.VirtualSize;
                Module_TarSecEnd_RVA = Module_TarSec_RVA + Module_TarSec_Size;
                goto __Get_target_sec;
            }
            num--;
        }
        printf_s("Get Target Section Fail !\n");
        return 0;
    }
    return 0;

__Get_target_sec:
    DWORD64 address = 0;
    if (isGenshin)
    {
        DWORD64 Hook_addr = 0;
        DWORD64 Hook_addr_tar = 0;
        while(address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "CC 89 0D ?? ?? ?? ?? C3 CC"))//搜索正确patch点位
        {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip)+4;
            if ((rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) == _ptr_fps)
            {
                Hook_addr = address + 1;
                Hook_addr_tar = Hook_addr - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                goto __Get_Patch_addr;
            }
            else
            {
                *(uint64_t*)(address + 1) = 0xCCCCCCCCCCCCCCCC;
            }
        }
        printf_s("\nPatch pattern outdate...\n");
        return 0;

    __Get_Patch_addr:
        uint32_t Qword_num = 0;
        uint64_t Patch_addr = 0;
        uint64_t Patch_addr_Tar = 0;
        while (*(uint64_t*)(Module_TarSecEnd_RVA + (Qword_num * 8)) == 0)//获取区段尾部空余空间
        {
            Qword_num++;
            if (Qword_num == 9)
            {
                break;
            }
        }
        if (Qword_num >= 9)
        {
            //先在buffer里Patch好，再写到TarProcess
            Patch_addr = ((Module_TarSecEnd_RVA + 32)>>4)<<4;//对齐
            *(uint64_t*)(Patch_addr - 8) = 0xCCCCCCCCCCCCCCCC;
            *(uint64_t*)(Patch_addr - 16) = 0xCCCCCCCCCCCCCCCC;
            Patch_addr_Tar = (Patch_addr - 16) - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
            { //copy shellcode
                uint64_t * temp_ptr = (uint64_t*)Patch_addr;
                uint64_t * temp_ptr_sc = (uint64_t*)&_shellcode_genshin;
                int32_t pa_offset = 0;
                int i = 0;
                while(i!=6)
                {
                    *(uint64_t*)(temp_ptr + i) = *(uint64_t*)(temp_ptr_sc + i);
                    i++;
                }
                *(uint32_t*)(Patch_addr + 0x14) = FPS_TARGET;
                uint64_t RVA_fps = (_ptr_fps - (uintptr_t)unity_baseaddr)+ (uintptr_t)unity_module;
                *(uint32_t*)(Patch_addr + 0x24) = (uint32_t)(RVA_fps - (uint32_t)(Patch_addr + 0x28));
            }
            int32_t _jmp_im_num = Patch_addr - (Hook_addr + 5);//hook原来的set
            *(uint64_t*)Hook_addr = 0xCCCCCC00000000E9;
            *(uint32_t*)(Hook_addr + 1) = _jmp_im_num;
            //----------------------------------------------buffer_ok----------------------------------------------//
            if (WriteProcessMemory(Tar_handle, (LPVOID)Patch_addr_Tar, (LPVOID)(Patch_addr - 16), 0x40, 0) == 0)
            {
                DWORD ERR_code = GetLastError();
                printf_s("\nWrite Target_Patch Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                return 0;
            }
            if (WriteProcessMemory(Tar_handle, (LPVOID)Hook_addr_tar, (LPVOID)Hook_addr, 0x8, 0) == 0)
            {
                DWORD ERR_code = GetLastError();
                printf_s("\nWrite Target_Hook Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                return 0;
            }
            return (Patch_addr_Tar + 0x24);
        }
        printf_s("\nPatch Failed cause no enough space in module...\n");
        return 0;
    }
    else
    {
        while (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "CC 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC CC"))//搜索正确patch点位
        {
            uintptr_t rip = address;
            rip += 3;
            int32_t eax_fps_of = *(int32_t*)(rip);
            if ((eax_fps_of >> 31) == 1)
            {eax_fps_of += 5;}else { eax_fps_of -= 5; }
            int32_t ebx_jmp_im = *(int32_t*)(rip + 5);
            if ((ebx_jmp_im >> 31) == 1)
            { ebx_jmp_im += 5;}else { ebx_jmp_im -= 5; }
            rip += *(int32_t*)(rip)+4;
            if ((rip - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) == _ptr_fps)
            {
                DWORD64 Patch0_addr = address + 1;
                DWORD64 Patch0_addr_hook = Patch0_addr - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr;
                *(int64_t*)Patch0_addr = 0x000D8900000078B9;
                *(int64_t*)(Patch0_addr + 8) = 0x00000000E9000000;
                *(int32_t*)(Patch0_addr + 1) = FPS_TARGET;
                *(int32_t*)(Patch0_addr + 7) = eax_fps_of;
                *(int32_t*)(Patch0_addr + 12) = ebx_jmp_im;
                if (WriteProcessMemory(Tar_handle, (LPVOID)Patch0_addr_hook, (LPVOID)Patch0_addr, 0x10, 0) == 0)
                {
                    DWORD ERR_code = GetLastError();
                    printf_s("\nWrite Target_Patch Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                    return 0;
                }
                return ((address - (uintptr_t)unity_module + (uintptr_t)unity_baseaddr) + 2);
            }
            Module_TarSec_Size = address - Module_TarSec_RVA;
            Module_TarSec_RVA = address + 12;
        }
        printf_s("\nPatch pattern outdate...\n");
        return 0;
    }
}

// 热键线程
static DWORD __stdcall Thread_Key(LPVOID p)
{
    if (p == NULL)
    {
        MessageBoxW(_console_HWND,L"HotKeyThread get a Nullptr! \n",L"Error",0x10);
        return 0;
    }
    int* pTargetFPS = (int*)p;
    int fps = *pTargetFPS;
    int prev = fps;
    
    while (true)
    {

_update_state:
        Sleep(100); 
        if (Process_endstate)
        {
            break;
        }
        if ((GetForegroundWindow() != _console_HWND) && (isAntimiss == 1))
        {
            goto _update_state;
        }
        if (GetAsyncKeyState(KEY_TOGGLE) & 1)
        {
            _main_state = !_main_state;
        }
        if (!_main_state)
        {
            printf_s("\rFPS Now stop setting!           Press END key to continue.    ");
            goto _update_state;
        }
        if (GetAsyncKeyState(KEY_DECREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps -= 20;
        }
        if (GetAsyncKeyState(KEY_DECREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps -= 2;
        }
        if (GetAsyncKeyState(KEY_INCREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps += 20;
        }
        if (GetAsyncKeyState(KEY_INCREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps += 2;
        }
        if (fps <= 10)
        {
            fps = 10;
        }
        if ((GetForegroundWindow() == _console_HWND) && (GetAsyncKeyState(VK_LCONTROL) & 0x8000) && (GetKeyState(0x53) & 0x8000))
        {
            if (prev != fps)
            {
                if (WriteConfig(fps))
                {
                    prev = fps;
                    printf_s("\r Save success !                                                ");
                    Sleep(1000);
                }
            }
        }

        *pTargetFPS = fps;
        printf_s("\rFPS: %d - %s    %s", fps, fps < 30 ? "Low power state" : "Normal state   ","  Press END key stop change  ");
        
    }
    if (prev != fps)
    {
        WriteConfig(fps);
    }
    Process_endstate = 0;
    return 0;
}



static void FullScreen() 
{
    HANDLE Hand;
    CONSOLE_SCREEN_BUFFER_INFO Info;
    Hand = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(Hand, &Info);
    SMALL_RECT rect = Info.srWindow;
    COORD size = { rect.Right + 1 ,rect.Bottom + 1 };	//定义缓冲区大小，保持缓冲区大小和屏幕大小一致即可取消边框 
    SetConsoleScreenBufferSize(Hand, size);
}

int main(int argc, char** argv)
{
    
    SetConsoleTitleA("HoyoGameFPSunlocker");
    
    _console_HWND = GetConsoleWindow();

    if (_console_HWND == NULL)
    {
        MessageBoxW(0, L"Get console window failed!", L"Fatal Error", 0x10);
        return 0;
    }
    
    FullScreen();//禁用控制台滚动 disable console text roll

    std::string CommandLine{};
    if (argc >= 2)
    {
        std::string boot_genshin("-Genshin");
        std::string boot_starrail("-HKSR");
        if (argv[1] == boot_genshin)
        {
            printf_s("This console control GenshinFPS\n");
            SetConsoleTitleA("GenshinNow");
            if(argc > 2)
            {
                for (int i = 2; i < argc; i++)
                {
                    CommandLine += argv[i] + std::string(" ");
                }
            }
            goto __choose_ok;
            
        }else if(argv[1] == boot_starrail)
        {
            isGenshin = 0;
            printf_s("This console control HKStarRailFPS\n");
            SetConsoleTitleA("StarRailNow");
            printf_s("\nWhen V-sync is True need open Hotpatch and open setting then quit to apply change in StarRail. \n当垂直同步开启时解锁帧率需要开启热补丁模式进设置界面再退出才可成功解锁 \n");
            if (argc > 2)
            {
                for (int i = 2; i < argc; i++)
                {
                    CommandLine += argv[i] + std::string("");
                }
            }
            goto __choose_ok;
        }
        else 
        {
            MessageBoxW(_console_HWND, L"argv error ( unlocker.exe -[game] -[game argv] ) \n参数错误", L"Tip", 0x10);
        }
        
    }
    
    {
        int gtype = MessageBoxW(_console_HWND, L"Genshin click yes ,StarRail click no ,Cancel to Quit \n启动原神选是，崩铁选否，取消退出 \n", L"GameSelect ", 0x23);
        if (gtype == 2)
        {
            return 0;
        }
        if (gtype == 6)
        {
            printf_s("This console control GenshinFPS\n");
            SetConsoleTitleA("GenshinNow");
        }
        if (gtype == 7)
        {
            isGenshin = 0;
            printf_s("This console control HKStarRailFPS\n");
            SetConsoleTitleA("StarRailNow");
            printf_s("\nWhen V-sync is True need open Hotpatch and open setting then quit to apply change in StarRail. \n当垂直同步开启时解锁帧率需要开启热补丁模式进设置界面再退出才可成功解锁 \n");
        }
    }

__choose_ok:
    if (LoadConfig() == 0)
    {
        return 0;
    }

    DWORD TargetFPS = FpsValue;
    std::string ProcessPath = GamePath;
    std::string ProcessDir{};

    if (ProcessPath.length() < 8)
        return 0;

    printf_s("FPS unlocker v2.5.4\n");
    printf_s("\nThis program is Free and OpenSource in \n https://github.com/winTEuser/Genshin_StarRail_fps_unlocker \n这个程序开源,链接如上,请勿在其他地方下载,以免被套毒\n\n");
    cout << "GamePath: " << ProcessPath.c_str() << endl;
    ProcessDir = ProcessPath.substr(0, ProcessPath.find_last_of("\\"));
    std::wstring prcessname = to_wide_string(ProcessPath.substr(ProcessPath.find_last_of("\\") + 1));
    
_wait_process_close:
    DWORD pid = GetPID(prcessname);
    if (pid)
    {
        int state = MessageBoxW(NULL, L"Game has being running! \n游戏已在运行！\nYou can click yes to auto close game and restart or click cancel to manually close. \n点击确定自动关闭游戏或手动关闭游戏后点取消\n", L"Error", 0x11);
        if (state == 1)
        {
            HANDLE tempHandle = OpenProcess(PROCESS_TERMINATE, false, pid);
            TerminateProcess(tempHandle, 0);
            CloseHandle(tempHandle);
            Sleep(2000);
            goto _wait_process_close;
        }
        printf_s("Now close this console and reboot unlocker.\n现在可以重启解锁器\n");
        system("pause");
        return 0;
    }

    STARTUPINFOA si{};

    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(ProcessPath.c_str(), (LPSTR)CommandLine.c_str(), nullptr, nullptr, FALSE, 0, nullptr, ProcessDir.c_str(), &si, &pi))
    {
        DWORD ERR_code = GetLastError();
        printf_s("\nCreateprocess Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        system("pause");
        return (int)-1;
    }
    
    CloseHandle(pi.hThread);
    cout << "PID: "<< pi.dwProcessId << endl;

    Sleep(500);
    // 等待UnityPlayer.dll加载和获取DLL信息
    MODULEENTRY32 hUnityPlayer{};

    {
        DWORD times = 1000;
        while (!GetModule(pi.dwProcessId, L"UnityPlayer.dll", &hUnityPlayer))
        {
            Sleep(50);
            times -= 5;
            if (GetModule(pi.dwProcessId, L"unityplayer.dll", &hUnityPlayer))
            {
                goto __get_unity_ok;
            }
            if (times == 0)
            {
                cout << "Get unity module time out!" << endl;
                CloseHandle(pi.hProcess);
                system("pause");
                return (int) - 1;
            }
        }
    }
    
__get_unity_ok:

    cout <<"UnityPlayer: 0x" << setiosflags(ios::uppercase) << hex << (uintptr_t)hUnityPlayer.modBaseAddr <<endl;

    // 在本进程内申请UnityPlayer.dll大小的内存 - 用于特征搜索
    LPVOID up = VirtualAlloc(nullptr, hUnityPlayer.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!up)
    {
        DWORD ERR_code = GetLastError();
        printf_s("\nVirtualAlloc failed! ( 0x%X ) - %s", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        system("pause");
        CloseHandle(pi.hProcess);
        return (int)-1;
    }
    if (hUnityPlayer.modBaseAddr == 0)
    {
        printf_s("\nUnityPlayerBaseAddrptr is null ! \n");
        CloseHandle(pi.hProcess);
        system("pause");
        return (int)-1;
    }
    // 把整个模块读出来
    if (!ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, up, hUnityPlayer.modBaseSize, nullptr))
    {
        DWORD ERR_code = GetLastError();
        printf_s("\nRead UnityPlayer module Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        CloseHandle(pi.hProcess);
        VirtualFree(up, 0, MEM_RELEASE);
        system("pause");
        return (int)-1;
    }

    printf_s("Searching for pattern...\n");
    // 
    //starrail fps 66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0
    //Vsync 3B 15 ?? ?? ?? ?? 0F 84 86 00 00 00 48 89 74 24 40 40 84 FF 
    // 
    //7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8 
    // 
    //7F 0E E8 ? ? ? ? 66 0F 6E C8 0F 5B C9
    //
    // 计算相对地址 (FPS)

    //uintptr_t pVSync = 0;    //Game_Vsync_ptr
    //uintptr_t pVSync_fps = 0;//Game_Vsync_target_fps_ptr

    uintptr_t pfps = 0;      //normal_fps_ptr
    DWORD64 address = 0;
    if (isGenshin) 
    {  
        //GenShin
        //if(Vsync)
        //{
        //    uintptr_t address = PatternScan(up, "E8 ?? ?? ?? ?? 48 85 C0 74 15 48 63 48 ?? 48 8B 40 ?? 48 69 D1 ?? ?? ?? ?? 8B 5C 02 ?? ");
        //    if (address)
        //    {
        //        //uintptr_t ppvsync = 0;
        //        uintptr_t rip = address;
        //        int32_t rel = *(int32_t*)(rip + 1);
        //        rip = rip + rel + 5;
        //        int32_t ecx = *(int32_t*)(rip + 1);
        //        int32_t jmp_t = *(int32_t*)(rip + 6);
        //        rip = rip + 10 + jmp_t;
        //        rip += 3;
        //        uint64_t rax = *(uint32_t*)(rip + 3);
        //        uint64_t rcx = 0;
        //        if (*(uint32_t*)(rip + 7) == 0xC1048B48)
        //        {
        //            rip = rip + rax + 7;
        //            rax = rip + ecx * 8;
        //            uintptr_t realadd = rax - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
        //            while (*(uint64_t*)rax == 0)
        //            {
        //                if (!ReadProcessMemory(pi.hProcess, (LPCVOID)realadd, (LPVOID)rax, 8, 0))
        //                {
        //                    MessageBoxA(_console_HWND, "ReadProcessMemory_vsync_1", "Error", 0x10);
        //                }
        //            }
        //            rax = *(uint64_t*)rax;
        //            rcx = *(uint8_t*)(address + 13);
        //            rcx = rax + rcx;
        //            realadd = 0;
        //            while (realadd == 0)
        //            {
        //                if (!ReadProcessMemory(pi.hProcess, (LPCVOID)rcx, &realadd, 4, 0))
        //                {
        //                    MessageBoxA(_console_HWND, "ReadProcessMemory_vsync_2", "Error", 0x10);
        //                }
        //            }
        //            rcx = realadd;
        //            rax = rax + *(uint8_t*)(address + 17);
        //            realadd = rax;
        //            rax = 0;
        //            while (rax == 0)
        //            {
        //                if (!ReadProcessMemory(pi.hProcess, (LPCVOID)realadd, &rax, 8, 0))
        //                {
        //                    MessageBoxA(_console_HWND, "ReadProcessMemory_vsync_3", "Error", 0x10);
        //                }
        //            }
        //            rcx = rcx * (*(uint32_t*)(address + 21));
        //            rax = rax + rcx + (*(uint8_t*)(address + 28));
        //            if (!ReadProcessMemory(pi.hProcess, (LPCVOID)rax, &rcx, 1, 0))
        //            {
        //                MessageBoxA(_console_HWND, "ReadProcessMemory_vsync_4", "Error", 0x10);
        //            }
        //            if ((rcx == 1) || (rcx == 0))
        //            {
        //                pVSync = rax;
        //            }
        //            else
        //            {
        //                printf_s("Genshin_Vsync_pattern_outdate!\n");
        //            }
        //        }
        //    }
        //}
        address = PatternScan(up, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - last 
        if (address)
        {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip)+6;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
            goto __offset_ok;
        }
        address = PatternScan(up, "7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8"); // ver old
        if (address)
        {
            uintptr_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
            goto __offset_ok;
        }
        MessageBoxA(_console_HWND, "Genshin Pattern Outdated!\nPlase wait new update in github.\n\n", "Error", 0x10);
        CloseHandle(pi.hProcess);
        VirtualFree(up, 0, MEM_RELEASE);
        return (int)-1;
        
    }
    else
    {   
        //HKSR
        //address = PatternScan(up, "3B 15 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48 89 74 24 40 40 84 FF"); //Vsync
        //if (address)
        //{
        //    uintptr_t rip = address;
        //    uint64_t rax = 0;
        //    rip += 2;
        //    rip += *(int32_t*)(rip)+4;
        //    pVSync_fps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
        //    pVSync = pVSync_fps - 4;
        //    uintptr_t pVSync_en = pVSync + 4;
        //    //Patch_Vsync_set
        //    *(int16_t*)(address + 6) = 0xE990;
        //    *(int16_t*)(address + 12) = 0xF8EB;
        //    rax = *(int64_t*)(address + 6);
        //    rip = address - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
        //    rip += 6;
        //    if (!WriteProcessMemory(pi.hProcess, (LPVOID)rip, &rax, 8, 0))//Patch_Vsync_set
        //    {
        //        MessageBoxA(_console_HWND, "WriteProcessMemory_Vsync_0_Fail", "Error", 0x10);
        //    }
        //    rax = 0;
        //    if (!WriteProcessMemory(pi.hProcess, (LPVOID)pVSync_en, &rax, 4, 0))//Disable_Vsync_en
        //    {
        //        MessageBoxA(_console_HWND, "WriteProcessMemory_Diseable_Vsync_1_Fail", "Error", 0x10);
        //    }
        //}
        //else
        //{
        //    MessageBoxA(_console_HWND, "StarRail_Vsync_pattern_outdate!\n", "Error", 0x10);
        //}
        address = PatternScan(up, "66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0"); //ver 1.0 - last
        if (address)
        {
            uintptr_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
            goto __offset_ok;
        }
        MessageBoxA(_console_HWND, "StarRail Pattern Outdated!\nPlase wait new update in github.\n\n", "Error", 0x10);
        CloseHandle(pi.hProcess);
        VirtualFree(up, 0, MEM_RELEASE);
        return (int)-1;
    }
    //-----------------------------------------------------------------------------------------------------------------//

__offset_ok:
    
    uintptr_t Patch_ptr;
    if(isHotpatch == 1)
    {
        Patch_ptr = inject_patch(up, (DWORD64)hUnityPlayer.modBaseAddr, pfps, pi.hProcess);//45 patch config
        if (Patch_ptr == NULL)
        {
            printf_s("Inject Patch Fail!\n\n");
        }
    }
    VirtualFree(up, 0, MEM_RELEASE);

    cout <<"FPS Offset: 0x" << setiosflags(ios::uppercase) << hex << pfps << "\n" << endl;
  
    cout <<"\nUse Right Ctrl Key with ↑↓←→ key to change fps limted\n使用键盘上的右Ctrl键和方向键调节帧率限制\n\n" <<endl;
    
    cout <<"  Rctrl + ↑ : +20\n  Rctrl + ↓ : -20\n  Rctrl + ← : -2 \n  Rctrl + → : +2 \n\n"<<endl;

    // 创建热键线程
    HANDLE hThread = CreateThread(0, 0, Thread_Key, &TargetFPS, 0, 0);
    if (hThread == NULL)
    {
        DWORD ERR_code = GetLastError();
        printf_s("\nCreate HotkeyThread Fail! ( 0x%X ) - %s\n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
        CloseHandle(pi.hProcess);
        system("pause");
        return 0;
    }
    CloseHandle(hThread);

    DWORD dwExitCode = STILL_ACTIVE;
    int32_t fps = 0; //game real
    while (1)
    {
        if (_main_state)
        {
            if ((ReadProcessMemory(pi.hProcess, (LPVOID)pfps, &fps, sizeof(fps), nullptr)) == NULL)
            {
                DWORD ERR_code = GetLastError();
                if (ERR_code == ERROR_ACCESS_DENIED && isHotpatch == 0)
                {
                    printf_s("\nRead mem failed(0x5 ERROR_Access_Denied), May mem protect has load,try again with open hotpatch\n权限拒绝(0x5)可能内存保护已经完全加载 可以尝试开启热修补 \n");
                }
                else
                {
                    printf_s("\nRead Target_fps Fail! ( 0x%X ) - %s \n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                }
                goto __exit_main;
            }
            if (fps != TargetFPS)
            {
                if ((WriteProcessMemory(pi.hProcess, (LPVOID)pfps, &TargetFPS, sizeof(TargetFPS), nullptr)) == NULL)
                {
                    DWORD ERR_code = GetLastError();
                    if (ERR_code == ERROR_ACCESS_DENIED && isHotpatch == 0)
                    {
                        printf_s("\nWrite mem failed(0x5 ERROR_Access_Denied), May mem protect has load,try again with open hotpatch\n权限拒绝(0x5)可能内存保护已经完全加载 可以尝试开启热修补 \n");
                    }
                    else
                    {
                        printf_s("\nWrite Target_fps Fail! ( 0x%X ) - %s \n", ERR_code, GetLastErrorAsString(ERR_code).c_str());
                    }
                    goto __exit_main;
                }
                if (TargetFPS >= 120 )
                {
                    SetPriorityClass(pi.hProcess, REALTIME_PRIORITY_CLASS);
                }
                if (TargetFPS <= 90 && TargetFPS >= 60)
                {
                    SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);
                }
                if (TargetFPS <= 60)
                {
                    SetPriorityClass(pi.hProcess, NORMAL_PRIORITY_CLASS);
                }
                if (TargetFPS <= 30)
                {
                    SetPriorityClass(pi.hProcess, BELOW_NORMAL_PRIORITY_CLASS);
                }
                if(isHotpatch && Patch_ptr)
                {
                    if ((WriteProcessMemory(pi.hProcess, (LPVOID)Patch_ptr, &TargetFPS, sizeof(TargetFPS), nullptr)) == NULL)
                    {
                        DWORD ERR_code = GetLastError();
                        if (ERR_code == ERROR_ACCESS_DENIED)
                        {
                            printf_s("\nWrite failed(0x5 ERROR_Access_Denied), May mem protect has load.\n权限拒绝(0x5)可能内存保护已经完全加载 \n");
                        }
                        goto __exit_main;
                    }
                }
            }
        }
        Sleep(500);
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        if (dwExitCode != STILL_ACTIVE)
        {
            printf_s("\nGame Terminated !\n");
            break;
        }
    }

__exit_main:
    CloseHandle(pi.hProcess);
    Process_endstate = 1;
    while (Process_endstate)
    {
        Sleep(100);
    }
    system("pause");
   
    return 1;
}








