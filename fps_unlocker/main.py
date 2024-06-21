import argparse
from pathlib import Path
import psutil
from typing import Tuple, Optional
from time import sleep
import configparser
import ctypes
import sys
import keyboard
import subprocess
import os
from utils import *


def write_config(game_path: Path, fps_value: int):
    config = configparser.ConfigParser()
    config["fps_unlocker"] = {
        "game_path": str(game_path),
        "fps_value": str(fps_value)
    }
    with open(CONFIG_PATH, "w") as configfile:
        config.write(configfile)


def init_config():
    print("Config file not found, creating one...")
    print("please launch 'YuanShen.exe' or 'GenshinImpact.exe' to finish the setup")
    print("\nwaiting for the game to launch...")

    pid = -1
    while pid == -1:
        pid = max(get_pid("YuanShen.exe"), get_pid("GenshinImpact.exe"))
        sleep(0.2)
    game_path = get_executable_path(pid)
    write_config(game_path, FPS_VALUE)


def load_config() -> Optional[Tuple[Path, int]]:
    if not CONFIG_PATH.exists():
        init_config()
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    try:
        game_path = Path(config.get("fps_unlocker", "game_path"))
        fps_value = config.getint("fps_unlocker", "fps_value")
        if not (is_valid_path(game_path) and is_valid_fps(fps_value)):
            raise InvalidConfigError("Invalid config file")
        return game_path, fps_value
    except (InvalidConfigError, configparser.Error) as e:
        print(e)
        CONFIG_PATH.unlink()
        return load_config()


def main():
    game_path, fps_value = load_config()
    args = load_args()
    if args.fps is not None or args.path is not None:
        fps_value = args.fps if args.fps is not None else fps_value
        game_path = args.path if args.path is not None else game_path
        if args.save is not None and args.save is True:
            write_config(game_path, fps_value)
            print(f"Config saved to {CONFIG_PATH}")
    print(f"Unlocking FPS to {fps_value} for {game_path}")
    # TODO make sure the game is closed, because we need to write to the game's memory in the next step


if __name__ == '__main__':
    if os.name != "nt":
        print("This script is only compatible with Windows.")
        exit(ERR_FAILURE)
    run_as_admin()
    main()
    press_any_key_to_continue()
