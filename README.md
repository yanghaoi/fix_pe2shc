# pe2shc — PE to Shellcode Converter

[![Platform](https://img.shields.io/badge/platform-Windows-blue)](https://github.com/yanghaoi/fix_pe2shc)
[![Language](https://img.shields.io/badge/language-C%2B%2B%2FMASM-yellow)](https://github.com/yanghaoi/fix_pe2shc)
[![Version](https://img.shields.io/badge/version-1.2--NoReloc-green)](https://github.com/yanghaoi/fix_pe2shc)

**pe2shc** 是一个将普通 PE 文件（`.exe` / `.dll`）转换为位置无关 shellcode 的工具集。支持有 `.reloc` 的标准重定位加载和无 `.reloc` 的 No-Reloc 模式，并内置了加载器存根（Loader stub）自动注入 shellcode 中。

## 工具组件

| 工具 | 说明 |
|------|------|
| **pe2shc** | PE → Shellcode 转换器，将 PE 文件与 Loader stub 合并，输出 `.shc.exe` |
| **runshc** | Shellcode 加载器，将 `.shc.exe` 读入内存并在新线程中执行 |
| **injector** | Shellcode 注入器，将 shellcode 注入到指定 PID 的远程进程 |
| **libpeconv** | PE 格式处理静态库（第三方依赖） |
| **loader_v2** | Loader stub 源码，编译为位置无关的 shellcode 存根 |

## 项目结构

```
.
├── pe2shc/                  # PE → Shellcode 转换器主程序
│   ├── main.cpp             # PE 读取、校验、转换、No-Reloc 风险检测
│   ├── resource.h           # 资源头文件
│   ├── resource2.rc         # 引用 stub2/*.bin 作为内嵌资源
│   └── stub2/               # Loader stub 编译产物 (.bin)
│       ├── stub32.bin       # 32-bit Loader stub
│       └── stub64.bin       # 64-bit Loader stub
├── loader_v2/               # Loader stub 源码
│   ├── peloader.cpp         # PE 手动映射 + 导入解析 + TLS 回调
│   ├── peloader.h           # min_hdr_t 结构体定义
│   └── peb_lookup.h         # PEB 遍历 + CRC32 查找 kernel32 导出函数
├── runshc/                  # Shellcode 加载器
│   └── main.cpp
├── injector/                # Shellcode 注入器
│   ├── main.cpp
│   ├── util.cpp
│   └── util.h
├── libpeconv/               # libpeconv 静态库（PE 处理）
├── test/                    # 测试程序
│   ├── test_msgbox.c        # 弹 MessageBox 的无 .reloc GUI 测试
│   └── test_nr.c            # 打印文字 + 返回 42 的无 .reloc Console 测试
├── extract_text.py          # 从 PE 提取 .text 段为 raw binary
├── CMakeLists.txt           # CMake 构建配置
├── build_all.bat            # 一键构建脚本
└── BUILD_AND_TEST.md        # 详细的构建与测试说明
```

## 工作原理

### .shc.exe 文件结构

```
┌─────────────────────────────┐
│  原始 PE 数据 (test.exe)    │
│  (头部已被重定向代码修改)   │
├─────────────────────────────┤
│  Loader Stub (stub64.bin)   │  ← 加载器代码
└─────────────────────────────┘
```

**运行时流程：**

```
Windows 加载 test.shc.exe
  → 入口点已被重定向到 stub 位置
  → Stub 执行:
      1. 通过 PEB 遍历查找 kernel32.dll
      2. CRC32 哈希解析 LoadLibraryA / GetProcAddress
      3. 检查 PE 头中 min_hdr.load_status
      4. 有 .reloc → 标准重定位 + 导入解析 + 执行
      5. 无 .reloc → In-Place 或 VirtualAlloc 模式加载
      6. 调用原始 PE 的入口点
```

### Loader Stub 编译流水线

```
peloader.cpp
  → cl /c /GS- /FA /O1        (生成 MASM 列表)
  → masm_shc.exe               (转换为位置无关 shellcode asm)
  → ml64 / link                (汇编链接成 PE)
  → extract_text.py            (提取 .text 段 → .bin)
```

## 命令行用法

### pe2shc — 转换 PE 为 Shellcode

```
用法: pe2shc <输入PE文件> [输出文件]

示例:
  pe2shc.exe test.exe             → 生成 test.shc.exe
  pe2shc.exe my.dll out.shc.exe   → 生成 out.shc.exe

说明:
  自动判断 PE 有无 .reloc 段：
    - 有 .reloc → 标准重定位加载流程
    - 无 .reloc → 进入 No-Reloc 模式
      并自动扫描 GS/SEH/CFG 等风险
```

### runshc — 加载执行 Shellcode

```
用法: runshc <shellcode文件>

示例:
  runshc.exe test.shc.exe     → 加载并执行 shellcode

说明:
  将 .shc.exe 读入 VirtualAlloc 分配的内存，
  在新线程中执行（Loader stub 接管 → 映射 PE → 调用入口点）
```

### injector — 注入 Shellcode 到远程进程

```
用法: injector <shellcode文件> <目标PID>

示例:
  injector.exe test.shc.exe 1234    → 注入到 PID 1234 进程

说明:
  VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
  将 shellcode 注入远程进程并执行
```

## No-Reloc 特性

### 1. No-Reloc 加载模式

PE 没有 `.reloc` 段时自动启用：

- **In-Place**: 已在 ImageBase → `VirtualProtect(RWX)` → 原地解析导入
- **VirtualAlloc**: 分配新内存 → 逐节复制 → 解析导入 → 执行

### 2. 风险检测

pe2shc 转换时会输出 `[WARN]` 检测以下风险项：

| 风险 | 说明 |
|------|------|
| `/GS Security Cookie` | 缓冲区安全检测，可能依赖 __security_cookie |
| `SEH Handler Table` | 异常处理表，需确保兼容 |
| `Control Flow Guard` | CFG 检查，可能会调用无可用 API |
| `Delay-load imports` | 延迟加载导入可能不可用 |
| `.bss` 段 | 未初始化数据段，自动零填充 |

### 3. 向后兼容

有 `.reloc` 的 PE 走原有加载路径，行为不变。

## 快速测试

```batch
:: 1) 生成无 .reloc 的测试 PE
cl /nologo /O1 /GS- test\test_nr.c /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /FIXED

:: 2) 用 pe2shc 转换为 shellcode
release\x64\pe2shc.x64.exe test_nr.exe

:: 3) 用 runshc 加载执行
release\x64\runshc.x64.exe test_nr.shc.exe

:: 预期输出:
:: [*] Reading module from: test_nr.shc.exe
:: >>> Creating a new thread...
:: No-Reloc PE Loaded OK!
:: Returning 42...
```

## 构建

详细构建步骤请参见 [BUILD_AND_TEST.md](BUILD_AND_TEST.md)。

### 依赖

| 工具 | 说明 |
|------|------|
| Visual Studio 2022 | 编译器工具链 |
| Windows SDK 10.0+ | Windows 头文件和库 |
| CMake 3.12+ | 构建系统 |
| [masm_shc](https://github.com/hasherezade/masm_shc) | 编译 Loader stub 必需工具 |

### 一键构建

```batch
build_all.bat
```

## 许可证

- **runshc** 使用的 `LICENSE` 文件位于 [runshc/LICENSE](runshc/LICENSE)
- **libpeconv** 为第三方依赖库，许可证请参考其原始仓库
- 其余代码许可证待补充

## 致谢

- [hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) — 原始项目
- [hasherezade/masm_shc](https://github.com/hasherezade/masm_shc) — MASM shellcode 转换工具
- [hasherezade/libpeconv](https://github.com/hasherezade/libpeconv) — PE 处理库