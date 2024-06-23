from pathlib import Path
from typing import Tuple
import configparser
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
    print(
        f"please launch '{YUANSHEN_EXE}' or '{GENSHIN_EXE}' to finish the setup."
    )
    print("\nwaiting for the game to launch...")

    # get pid of the game process
    pid = -1
    while pid == -1:
        pid = max(get_pid_by_name(YUANSHEN_EXE),
                  get_pid_by_name(GENSHIN_EXE))
        sleep(0.2)
    game_path = get_executable_path(pid)
    write_config(game_path, FPS_VALUE)


def load_config() -> Tuple[Path, int]:
    # load config file if it exists, otherwise create one
    if not CONFIG_PATH.exists():
        init_config()
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    try:
        game_path = Path(config.get("fps_unlocker", "game_path"))
        fps_value = config.getint("fps_unlocker", "fps_value")
        return game_path, fps_value
    except configparser.Error as e:
        # if config file is invalid, delete it
        print(e)
        CONFIG_PATH.unlink()
    return None, None


def get_valid_fps(fps_value: int) -> int:
    # if fps_value is not valid, use default value
    return fps_value if is_valid_fps(fps_value) else FPS_VALUE


def get_valid_path(game_path: Path) -> Path:
    # if game_path is not valid, delete config and reinitialize
    if not is_valid_file(game_path):
        CONFIG_PATH.unlink()
        game_path = load_config()[0]
    return game_path


def get_valid_path_fps() -> Tuple[Path, int]:
    # use args if provided, otherwise load from config
    args = load_valid_args()
    configs = load_config()
    game_path = args.path if args.path else get_valid_path(configs[0])
    fps_value = args.fps if args.fps else get_valid_fps(configs[1])
    return game_path, fps_value


def fps_unlocker(game_path: Path, fps_value: int):
    args = [
        '--path',
        f'"{str(game_path)}"'.replace('/', '\\'),
        '--fps', str(fps_value)
    ]
    cmd = " ".join(args)
    print("Geshin Impact launch!!! 原神 启动！！")
    run_exe_as_admin(UNLOCKER_EXE, cmd)


def main():
    # get game path and fps value
    game_path, fps_value = get_valid_path_fps()

    # wait for the game to close
    running_pid = get_pid_by_path(game_path)
    if running_pid != -1:
        print("Please close the game before continuing.")
        wait_for_process_to_close(running_pid)

    # launch the game with the unlocked fps
    fps_unlocker(game_path, fps_value)


if __name__ == '__main__':
    must_run_on_windows()
    run_as_admin()
    main()
    # press_any_key_to_continue()
