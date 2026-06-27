# pe2shc — No-Reloc Shellcode Converter

## 环境准备

### 依赖

| 工具 | 路径 |
|------|------|
| Visual Studio 2022 | `D:\Program Files\Microsoft Visual Studio\2022\Community` |
| Windows SDK 10.0.26100 | `D:\Windows Kits\10` |
| CMake | `D:\BuildTools\winlibs\mingw64\bin\cmake.exe` |
| masm_shc.exe | `D:\Source\pe_to_shellcode\masm_shc.exe` |

> `masm_shc.exe` 是编译 loader 存根（stub）必需的工具，来自 [hasherezade/masm_shc](https://github.com/hasherezade/masm_shc)

### 首次构建

```batch
:: 打开 "Developer Command Prompt for VS 2022" 或手动调用:
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

:: 进入项目目录
cd /d D:\Source\pe_to_shellcode

:: 创建构建目录
if exist build_msvc_nr rmdir /s /q build_msvc_nr
mkdir build_msvc_nr
cd build_msvc_nr

:: CMake 配置
cmake .. -G "Ninja" -DCMAKE_CXX_COMPILER=cl -DCMAKE_C_COMPILER=cl -DCMAKE_BUILD_TYPE=Release -DPE2SHC_BUILD_TESTING=OFF
:: 如果 Ninja 不可用，用:
:: cmake .. -G "Visual Studio 17 2022" -A x64 -DPE2SHC_BUILD_TESTING=OFF

:: 编译
cmake --build . --config Release --target pe2shc
cmake --build . --config Release --target runshc
```

产物位置：
- `build_msvc_nr\pe2shc\pe2shc.exe`
- `build_msvc_nr\runshc\runshc.exe`

---

## 编译 Loader Stub（修改后的再生产物）

如果修改了 `loader_v2\peloader.cpp`，需要重新编译 stub：

### 64-bit

```batch
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d D:\Source\pe_to_shellcode\loader_v2

:: 编译出 MASM 列表
cl /c /GS- /FA /O1 peloader.cpp

:: 转换为位置无关 shellcode asm
masm_shc.exe peloader.asm stub64_new.asm

:: 修复 masm_shc 可能在 PROC 内部插入 CONST SEGMENT 的问题
:: （用文本编辑器打开 stub64_new.asm，删除所有 "CONST SEGMENT" 和 "CONST ENDS" 行）

:: 汇编链接
ml64 stub64_new.asm /link /entry:AlignRSP
```

提取 `.text` 段为 stub 二进制：

```batch
python D:\Source\pe_to_shellcode\extract_text.py stub64_new.exe ..\pe2shc\stub2\stub64.bin
```

### 32-bit

```batch
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
cd /d D:\Source\pe_to_shellcode\loader_v2

cl /c /GS- /FA /O1 peloader.cpp
masm_shc.exe peloader.asm stub32_new.asm
:: 同上，删除 CONST SEGMENT / CONST ENDS 行
ml stub32_new.asm /link /entry:main
python D:\Source\pe_to_shellcode\extract_text.py stub32_new.exe ..\pe2shc\stub2\stub32.bin
```

> **注意**：编译 64-bit 和 32-bit 需要先分别运行对应的 vcvarsall 环境（`x64` / `x86`）。

---

## 测试方式

### 1. 生成无 .reloc 的测试 PE

```batch
call "D:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d D:\Source\pe_to_shellcode

:: MessageBox 测试（GUI）
cl /nologo /O1 /GS- test_msgbox.c /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup /FIXED user32.lib

:: Console 测试（打印文字，返回 42）
cl /nologo /O1 /GS- test_nr.c /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /FIXED
```

### 2. 转换为 shellcode

```batch
build_msvc_nr\pe2shc\pe2shc.exe test_msgbox.exe
build_msvc_nr\pe2shc\pe2shc.exe test_nr.exe
```

### 3. 运行 shellcode

**方式 A：用 runshc 加载（推荐）**

```batch
build_msvc_nr\runshc\runshc.exe test_nr.shc.exe
```

预期输出：
```
[*] Reading module from: test_nr.shc.exe
>>> Creating a new thread...
[*] Running the shellcode [xxx - yyy]
No-Reloc PE Loaded OK!
Returning 42...
```

**方式 B：直接运行（In-Place 模式）**

```batch
test_nr.shc.exe
```

### 测试场景对比

| 场景 | 命令 | 预期 |
|------|------|------|
| 有 .reloc 的 PE 转换 | `pe2shc test_prog.exe` | 走标准重定位路径 |
| 无 .reloc 的 PE 转换 | `pe2shc test_nr.exe` | 打印 no-reloc 警告 + 风险检测 |
| runshc 加载 no-reloc shellcode | `runshc test_nr.shc.exe` | VirtualAlloc + 复制 → 执行 |
| 直接运行 no-reloc shellcode | `test_nr.shc.exe` | 检测到在 ImageBase → In-Place 模式 |

---

## 特性说明

### 1. No-Reloc 模式（核心）

当输入的 PE 文件没有 `Base Relocation Directory`（`.reloc` 段）时，自动启用。

```
检测 DataDirectory[BASE_RELOC].Size == 0
  │
  ├─ In-Place 模式（module_base == ImageBase）
  │   └─ VirtualProtect(整个 image, RWX) → 原地解析 IAT → 调用 EP
  │
  └─ VirtualAlloc 模式（module_base ≠ ImageBase，如 runshc 注入）
      ├─ VirtualAlloc(ImageBase, SizeOfImage)
      │   └─ 失败 → VirtualAlloc(NULL, SizeOfImage)
      ├─ 逐节复制（volatile BYTE* 防 memcpy 优化）
      ├─ 解析 IAT
      └─ 调用入口点（loaded_img + EP_RVA）
```

### 2. 风险检测

对无 .reloc 的 PE 自动扫描以下风险：

| 风险项 | 检测方法 | 输出 |
|--------|---------|------|
| `/GS` Security Cookie | LoadConfig → SecurityCookie != 0 | `[WARN] ...` |
| SEH handler table | LoadConfig → SEHandlerTable != 0 | `[WARN] ...` |
| Control Flow Guard | LoadConfig → GuardCFFunctionTable != 0 | `[WARN] ...` |
| Delay-load imports | `get_delayed_imps()` 非空 | `[WARN] ...` |
| `.bss` sections | SizeOfRawData==0 && VirtualSize>0 | `[WARN] ...`（自动零填充） |
| 大段对齐 > 64KB | SectionAlignment | `[WARN] ...` |

### 3. In-Place 模式

当 .shc.exe 被 Windows 直接加载运行时，`module_base == ImageBase`。此时跳过分配/复制，直接用 `VirtualProtect` 改成 RWX 后原地解析导入并执行，彻底消除 ImageBase 被占用的问题。

### 4. `.bss` 零填充

检测到 `SizeOfRawData == 0` 的段时自动零填充，避免从源文件复制脏数据。

### 5. 向后兼容

有 `.reloc` 的 PE 走原有路径（原地重定位 → 导入 → TLS → EP），无任何行为变化。

---

## Code Location

| 文件 | 说明 |
|------|------|
| `loader_v2\peloader.cpp` | Loader stub 主代码（编译为 shellcode） |
| `loader_v2\peloader.h` | `min_hdr_t` 结构定义 |
| `loader_v2\peb_lookup.h` | PEB 遍历 + CRC32 函数查址 |
| `pe2shc\main.cpp` | pe2shc 工具 + `scan_no_reloc_risks()` |
| `pe2shc\resource2.rc` | 资源文件，引用 `stub2\stub32.bin` / `stub2\stub64.bin` |
| `pe2shc\stub2\` | 预编译的 loader stub 二进制 |
