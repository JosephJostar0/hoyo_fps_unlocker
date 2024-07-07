en_US [English](./README.md) | zh_CN [简体中文](./README_CN.md)

# hoyo_fps_unlocker
A GenshinImpact FPS unlock tool

## Abstract

- This tool remove the fps limit for the latest version (V4.7) of GenshinImpact.
- Supports both Chinese and International editions.
- This tool is made with reference to the code of its developer.
- This tool was created to meet my personal needs, and it will be updated and maintained as long as I continue playing GenshinImpact.
- If you require addtional functionality, you can use other similar tools mentioned in [Reference](#reference).

## Latest Update (6/23/2024)

- Fixed the issues of disappearing constructs like Xiangling's Guoba and Yaoyao's Yuegui, as well as Elemental Shard.
- Ensures unlocked FPS during Abyss runs and quests.

## How to Use

0. Download the 7z package from [release](https://github.com/JosephJostar0/hoyo_fps_unlocker/releases) and extract it.
    - You will find two executable files: `unlocker_ui.exe` and `core.exe`.
    - **Warning**: You can place these files anywhere you want ***except*** for the game folder.

1. Run `unlocker_ui.exe`. 
    - If it's your first time using the tool, follow the instructions displayed in the tool's window.
    - You'll be prompted to start and then close the game manually to record its path.
    - After closing the game, the tool's window will be hidden, and the game will be restarted by the tool with unlocked FPS.

2. The game will launch automatically with the unlocked FPS.

3. Upon closing the game, the tool process will terminate automatically.

## Advanced

- You can modify game path or target FPS by editing `config.ini` in the same directory as `unlocker_ui.exe` and `core.exe`.

- Alternatively, you can pass arguments to `unlocker_ui.exe` instead of using config.ini
    - `--path YOUR_GAME_PATH` specifies the game path.
    - `--fps TAEGET_FPS` specifies the fps value you want to set.
    - `--debug 1` prevents the tool window from being hidden and displays debug information. 

    *tip*: If you don't provide the `path` or `fps` arguments, the tool will use the values from `config.ini`

- You can also use the `core.exe` directly by providing arguments and running it as administrator.
    - `--path YOUR_GAME_PATH` specifies the game path.
    - `--fps TARGET_FPS` specifies the fps value you want to set.

## Compile the Executable Files by Yourself

- For `core.exe`:  
    - Compile using Visual Studio with the provided source code in [unlocker.cpp](./fps_unlocker/unlocker.cpp).
    - If using a different compiler like g++ or clang++, ensure you adjust the source code to meet the compiler's requirements.
    > **Special thanks to @[winTEuser](https://github.com/winTEuser)**

- For `unlocker_ui.exe`:  
    - Make sure to install the necessary requirements before compiling.
    - Compile [main.py](./fps_unlocker/main.py) using PyInstaller.

## Notes

- HoYoverse (米哈游, miHoYo) acknowledges this tool, and I've used it for over six months without being banned.
- Use of other third-party plugins is at your own risk.
- Please refrain from reselling such a simple tool.

## Reference

- [Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker) @ winTEuser

- [genshin-fps-unlock](https://github.com/34736384/genshin-fps-unlock) @ 34736384

- [genshin-fps-unlock](https://github.com/xiaonian233/genshin-fps-unlock) @ xiaonian233

- [genshin-fps-bypass](https://github.com/RealistikDash/genshin-fps-bypass/tree/main) @ RealistikDash
