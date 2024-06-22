import argparse
from pathlib import Path
import keyboard
import psutil
import sys
from time import sleep
import os
import subprocess
import ctypes
from ctypes import wintypes
from unlocker_constants import *
import re

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("GlblcntUsage", ctypes.wintypes.DWORD),
        ("ProccntUsage", ctypes.wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),  # 使用 c_void_p 处理指针类型
        ("modBaseSize", ctypes.wintypes.DWORD),
        ("hModule", ctypes.wintypes.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260)
    ]


def open_process(exe_path: Path, command_line: str = "") -> subprocess.Popen:
    return subprocess.Popen(
        [str(exe_path), command_line],
        shell=False,
    )


def get_process_handle(process: subprocess.Popen, access_rights: int) -> ctypes.wintypes.HANDLE:
    return ctypes.windll.kernel32.OpenProcess(access_rights, False, process.pid)


def read_memory(process_handle: ctypes.wintypes.HANDLE, address: ctypes.c_void_p, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    ctypes.windll.kernel32.ReadProcessMemory(
        process_handle, address, buffer, size, ctypes.byref(bytes_read))

    return buffer.raw[:bytes_read.value]


def get_memory_data(process, base_address, base_size) -> bytes:
    access_rights = (
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION
    )
    process_handle = get_process_handle(process, access_rights)
    print("Process handle:", process_handle)

    address_to_read = ctypes.c_void_p(base_address)
    data = read_memory(process_handle, address_to_read, base_size)
    print(type(data), len(data))
    return data


def get_module_info(process, module_name) -> MODULEENTRY32:
    h_module = MODULEENTRY32()
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
        0x00000008, process.pid)
    h_module.dwSize = ctypes.sizeof(MODULEENTRY32)
    result = ctypes.windll.kernel32.Module32First(
        snapshot, ctypes.byref(h_module))
    while result:
        if h_module.szModule.decode().lower() == module_name.lower():
            ctypes.windll.kernel32.CloseHandle(snapshot)
            return h_module
        result = ctypes.windll.kernel32.Module32Next(
            snapshot, ctypes.byref(h_module))
    ctypes.windll.kernel32.CloseHandle(snapshot)
    return None


def get_UnityEngine_dll(process) -> MODULEENTRY32:
    hUnityPlayer = None
    try:
        while hUnityPlayer is None:
            hUnityPlayer = get_module_info(process, UNITY_PLAYER_DLL)
            sleep(0.2)
        return hUnityPlayer
    except Exception as e:
        print(e)
        process.kill()
    return None


def pattern_scan(data: bytes, signature) -> int:
    pattern_parts = []
    for part in signature.split():
        if part == "??":
            pattern_parts.append(None)
        else:
            pattern_parts.append(int(part, 16))

    pattern_length = len(pattern_parts)
    data_length = len(data)
    for i in range(data_length - pattern_length + 1):
        match = True
        for j in range(pattern_length):
            if pattern_parts[j] is not None and data[i + j] != pattern_parts[j]:
                match = False
                break
        if match:
            print(f"Found pattern at position {i}-{i + pattern_length}")
            return i
    return 0


def run_as_admin():
    # Check if the script is running as admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # If not, relaunch the script as admin
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        exit(0)


def must_run_on_windows():
    if os.name != "nt":
        print("This script can only be run on Windows.")
        exit()


def get_pid_by_name(process_name: str = GENSHIN_EXE) -> int:
    for proc in psutil.process_iter():
        if proc.name() == process_name:
            return proc.pid
    return -1


def get_executable_path(pid: int) -> Path:
    try:
        process = psutil.Process(pid)
        return Path(process.exe())
    except psutil.NoSuchProcess:
        print("Process not found")
        return None
    except psutil.AccessDenied:
        print("Access denied")
        return None


def get_pid_by_path(exe_path: Path) -> int:
    for proc in psutil.process_iter():
        try:
            if proc.exe() == str(exe_path):
                return proc.pid
        except:
            pass
    return -1


def wait_for_process_to_close(running_pid: int, sleep_time: float = 0.2):
    while psutil.pid_exists(running_pid):
        sleep(sleep_time)


def press_any_key_to_continue():
    print("\nPress any key to continue...")
    keyboard.read_event(suppress=True)
    keyboard.read_event(suppress=True)


def is_valid_fps(fps: int) -> bool:
    try:
        return MIN_FPS <= fps <= MAX_FPS
    except:
        return False


def is_valid_file(path: Path) -> bool:
    try:
        return path.exists() and path.is_file()
    except:
        return False


def load_valid_args():
    parser = argparse.ArgumentParser(
        description='Unlock FPS in Genshin Impact')
    parser.add_argument('--fps', type=int, help="FPS to unlock")
    parser.add_argument('--path', type=Path,
                        help="Path to the game executable")
    parser.add_argument('--save', type=bool, default=False,
                        help="Save the current configuration")
    try:
        args = parser.parse_args()
        # if fps is provided, check if it is valid
        if args.fps is not None and not is_valid_fps(args.fps):
            parser.error(
                "Invalid FPS value, must be between 1 and 65535: "
                + f"'{args.fps}'"
            )
        # if path is provided, check if it is valid
        if args.path is not None and not is_valid_file(args.path):
            parser.error(
                "Invalid path, the game executable does not exist: "
                + f"'{args.path}'"
            )
        return args
    except SystemExit:
        press_any_key_to_continue()
        exit(0)
