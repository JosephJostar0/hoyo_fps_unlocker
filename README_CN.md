en_US [English](./README.md) | zh_CN [简体中文](./README_CN.md)

# hoyo_fps_unlocker

一个解除原神帧率限制的工具。

## 摘要

- 此工具用于解除原神最新版本(V4.7)的FPS限制。
- 支持国服和国际服。
- 这个工具是在参考其他开发者的代码上制作的。
- 制作这个工具是为了满足我个人的需要；只要我还在玩原神，这个工具就将得到更新和维护。
- 如果你需要其他功能，可以使用[参考](#参考)中提到的其他类似工具。

## 最近更新 (2024.6.23)

- 修复了香菱的锅巴、瑶瑶的月桂以及元素结晶消失的问题。
- 保证在深渊和任务中FPS仍然解锁。

## 使用方法

0. 从[发布页]()下载7z压缩包并解压。
    - 你会找到两个可执行文件：`unlocker_ui.exe`和`core.exe`。
    - **警告**：你可以将这些文件放在任何地方，***除了***游戏文件夹。
1. 运行`unlocker_ui.exe`。
    - 如果这是你第一次使用此工具，请按照工具窗口中显示的指示操作。
    - 你需要手动启动并关闭游戏以记录游戏路径。
    - 关闭游戏后，工具窗口会隐藏，并且工具会重新启动游戏，解除FPS限制。
2. 游戏将自动启动并解除FPS限制。
3. 关闭游戏后，工具进程将自动终止。

## 高级用法

- 你可以通过编辑与`unlocker_ui.exe`和`core.exe`在同一目录下的`config.ini`文件来修改游戏路径或目标FPS。

- 你也可以通过传递参数给`unlocker_ui.exe`而不使用`config.ini`：
    - `--path YOUR_GAME_PATH`指定游戏路径。
    - `--fps TARGET_FPS`指定你想设置的FPS值。
    - `--debug 1`防止工具窗口隐藏并显示调试信息。
    *提示*：如果你没有提供`path`或`fps`参数，工具将使用`config.ini`中的值。

- 你也可以通过提供参数并以管理员身份运行`core.exe`直接使用它：
    - `--path YOUR_GAME_PATH`指定游戏路径。
    - `--fps TARGET_FPS`指定你想设置的FPS值。

## 自行编译可执行文件

- 对于`core.exe`：
    - 使用Visual Studio根据[unlocker.cpp](./fps_unlocker/unlocker.cpp)中提供的源代码进行编译。
    - 如果使用其他编译器如g++或clang++，确保你修改源代码以满足编译器的要求。
    > **特别感谢 @[winTEuser](https://github.com/winTEuser)**

- 对于`unlocker_ui.exe`：
    - 在编译前确保安装必要的依赖项。(requirements.txt)
    - 使用PyInstaller编译[main.py](./fps_unlocker/main.py)

## 注意事项

- 米哈游（miHoYo，HoYoverse）知晓帧率解锁工具的存在，但我已使用帧率解锁超过6个月的时间且账号未被封禁。
- 使用其他第三方插件请自行承担风险。
- 这么一个简单的小工具请勿转售。

## 参考

- [Genshin_StarRail_fps_unlocker](https://github.com/winTEuser/Genshin_StarRail_fps_unlocker) @ winTEuser

- [genshin-fps-unlock](https://github.com/34736384/genshin-fps-unlock) @ 34736384

- [genshin-fps-unlock](https://github.com/xiaonian233/genshin-fps-unlock) @ xiaonian233

- [genshin-fps-bypass](https://github.com/RealistikDash/genshin-fps-bypass/tree/main) @ RealistikDash
