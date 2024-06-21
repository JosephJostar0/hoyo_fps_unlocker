import argparse
from pathlib import Path
import psutil
import ctypes
import sys
import keyboard
from fps_constants import *


class InvalidConfigError(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __str__(self) -> str:
        return super().__str__()


def run_as_admin():
    # Check if the script is running as admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # If not, relaunch the script as admin
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        exit(0)


def press_any_key_to_continue():
    print("\nPress any key to continue...")
    keyboard.read_event(suppress=True)
    keyboard.read_event(suppress=True)


def is_valid_fps(fps: int) -> bool:
    try:
        return MIN_FPS <= fps <= MAX_FPS
    except:
        return False


def is_valid_path(path: Path) -> bool:
    try:
        return path.exists() and path.is_file()
    except:
        return False


def load_args():
    parser = argparse.ArgumentParser(
        description='Unlock FPS in Genshin Impact')
    parser.add_argument('--fps', type=int, help="FPS to unlock")
    parser.add_argument('--path', type=Path,
                        help="Path to the game executable")
    parser.add_argument('--save', type=bool, default=False,
                        help="Save the current configuration")
    try:
        args = parser.parse_args()
        if args.fps is not None and not is_valid_fps(args.fps):
            parser.error("Invalid FPS value, must be between 1 and 65535")
        if args.path is not None and not is_valid_path(args.path):
            parser.error("Invalid path, the game executable does not exist")
        return args
    except SystemExit:
        press_any_key_to_continue()
        exit(0)


def get_pid(process_name: str = "GenshinImpact.exe") -> int:
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
