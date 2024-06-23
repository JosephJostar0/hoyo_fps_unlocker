import argparse
import keyboard
import psutil
import sys
from time import sleep
import os
import ctypes
from unlocker_constants import *

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


def run_as_admin():
    # Check if the script is running as admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # If not, relaunch the script as admin
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        exit(0)


def run_exe_as_admin(exe_path: str, params: str = ""):
    # 调用ShellExecuteW函数，以管理员权限运行.exe程序
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe_path, params, None, 1)


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


def wait_for_process_to_close(running_pid: int, sleep_time: float = 0.5):
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
