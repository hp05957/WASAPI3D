# WASAPI3D 🎧

**WASAPI3D** is a lightweight, drop-in DLL proxy for Windows 7 that emulates modern Windows 10/11 audio interfaces (`ISpatialAudioClient`, `IAudioClient2`, and `IAudioClient3`). 

By intercepting modern 3D audio calls and downmixing them to standard Windows 7 WASAPI stereo, this tool fixes silent audio, startup crashes, and game speed-up bugs (desyncs) in modern DirectX 12 and Windows 10-only PC ports.

## ✨ Features

* **Spatial Audio Emulation:** Fools games into thinking Windows Sonic / Dolby Atmos 3D object audio is available via `ISpatialAudioClient`, downmixing spatial 3D objects dynamically to stereo.
* **Low-Latency Audio Bridging:** Wraps `IAudioClient2` and `IAudioClient3` calls, safely falling back to standard Windows 7 `IAudioClient` shared-mode streams.
* **Hardware Clock Pacing:** Uses High-Resolution Timers (QPC) and WASAPI buffer padding checks to perfectly pace the game's audio thread to 10ms hardware ticks. This entirely prevents the "game running at 2x speed" bug common in emulated audio wrappers.
* **Safe COM Hooking:** Thread-safe vtable hooking ensures stability without corrupting standard `MMDeviceAPI` enumerators.
* **Built-in Diagnostics:** Generates a real-time log file (`u4_spatial_proxy.log`) to help debug crashes and monitor audio object activation.

## 🎮 Tested Games

* **Uncharted: Legacy Of Theives Collection**
* *(More games will be tested later)*

## 🛠️ Installation

1. Download or compile `version.dll`.
2. Place `version.dll` directly into the game's installation folder (where the main game `.exe` is located).
3. Launch the game.

*Note: If the game doesn't automatically load `version.dll`, you can rename it to `winmm.dll`, `xinput1_4.dll`, or load it via an ASI Loader/VxKex depending on the game's import table.*

## 🏗️ Building from Source

You can easily build WASAPI3D using either MinGW-w64 or MSVC. The project requires `version_proxy.cpp` and a standard `version.def` exports file.

### MinGW-w64 (64-bit)
```bash
x86_64-w64-mingw32-g++ -O2 -shared -static-libgcc -static-libstdc++ version_proxy.cpp version.def -lole32 -lwinmm -luuid -o version.dll
```

### MSVC (x64 Native Tools Command Prompt)
```bat
cl /O2 /LD /EHsc version_proxy.cpp /link /DEF:version.def ole32.lib winmm.lib uuid.lib /OUT:version.dll
```

## 📝 Logging and Troubleshooting

When the proxy is loaded, it will automatically generate a log file named `u4_spatial_proxy.log` in the game directory. If you experience crashes, check this file. It includes a built-in vectored exception handler that will dump the crash address, registers, and module offsets to help you pinpoint the issue.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.