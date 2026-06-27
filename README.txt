===============================================================================
 pe2shc — PE to Shellcode Converter  (v1.2, No-Reloc)
===============================================================================

一、目录说明
───────────────────────────────────────────────────────────────────────────────

src/pe2shc/           pe2shc 主程序源码
  - main.cpp          PE 读取、校验、转换、no-reloc 风险检测
  - resource2.rc      引用 stub2/*.bin 作为内嵌资源

src/loader_v2/        Loader stub 源码（编译为 shellcode 存根）
  - peloader.cpp      Loader 主逻辑：PE 手动映射 + 导入解析 + TLS
  - peloader.h        min_hdr_t 结构（重定向 + 加载状态）
  - peb_lookup.h      通过 PEB 遍历 + CRC32 查找 kernel32 导出函数

src/runshc/           runshc 源码
  - main.cpp          将 .shc.exe 读入内存 → 新线程执行

src/injector/         injector 源码
  - main.cpp          将 shellcode 注入目标进程
  - util.cpp/util.h   文件读取工具函数

src/libpeconv/        libpeconv 静态库（第三方依赖）
                      处理 PE 格式、加载、转储、导入导出等

src/test/             测试文件
  - test_msgbox.c     弹 MessageBox 的无 .reloc GUI 测试程序
  - test_nr.c         打印文字 + 返回 42 的无 .reloc 控制台测试程序

tools/
  - masm_shc.exe      将 MSVC 编译的 MASM 列表 → 位置无关 shellcode asm
  - extract_text.py   从 PE 文件中提取 .text 段为 raw binary


二、生成的 EXE 说明
───────────────────────────────────────────────────────────────────────────────

  pe2shc.exe          把普通 PE (.exe/.dll) 转换为 shellcode 格式

  runshc.exe          加载 .shc.exe 文件，在新线程中作为 shellcode 执行

  injector.exe        将 shellcode 注入到指定 PID 的远程进程中


三、命令行用法
───────────────────────────────────────────────────────────────────────────────

┌─ pe2shc ─────────────────────────────────────────────────────────────┐
│                                                                      │
│  用法: pe2shc <输入PE文件> [输出文件]                                │
│                                                                      │
│  示例:                                                               │
│    pe2shc.exe test.exe                  → 生成 test.shc.exe          │
│    pe2shc.exe my.dll out.shc.exe        → 生成 out.shc.exe           │
│                                                                      │
│  说明:                                                               │
│    自动判断 PE 有无 .reloc 段：                                      │
│      - 有 .reloc → 标准重定位加载流程                                │
│      - 无 .reloc → 进入 No-Reloc 模式                                │
│        并自动扫描 GS/SEH/CFG 等风险                                   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

┌─ runshc ─────────────────────────────────────────────────────────────┐
│                                                                      │
│  用法: runshc <shellcode文件>                                        │
│                                                                      │
│  示例:                                                               │
│    runshc.exe test.shc.exe            → 加载并执行 shellcode         │
│                                                                      │
│  说明:                                                               │
│    把 .shc.exe 读入 VirtualAlloc 分配的内存，                        │
│    在新线程中执行（Loader stub 接管 → 映射 PE → 调用入口点）。      │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

┌─ injector ───────────────────────────────────────────────────────────┐
│                                                                      │
│  用法: injector <shellcode文件> <目标PID>                             │
│                                                                      │
│  示例:                                                               │
│    injector.exe test.shc.exe 1234     → 注入到 PID 1234 进程         │
│                                                                      │
│  说明:                                                               │
│    VirtualAllocEx → WriteProcessMemory → CreateRemoteThread           │
│    将 shellcode 注入远程进程并执行。                                  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘


四、完整测试流程
───────────────────────────────────────────────────────────────────────────────

  :: 1) 生成无 .reloc 的测试 PE
  cl /nologo /O1 /GS- test\test_nr.c /link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /FIXED

  :: 2) 用 pe2shc 转换为 shellcode
  release\x64\pe2shc.x64.exe test_nr.exe

  :: 3) 用 runshc 加载执行
  release\x64\runshc.x64.exe test_nr.shc.exe

  预期输出:
    [*] Reading module from: test_nr.shc.exe
    >>> Creating a new thread...
    No-Reloc PE Loaded OK!
    Returning 42...


五、No-Reloc 特性简要说明
───────────────────────────────────────────────────────────────────────────────

  1. No-Reloc 模式:
     PE 没有 .reloc 段时自动启用。
     - In-Place: 已在 ImageBase → VirtualProtect(RWX) → 原地解析导入
     - VirtualAlloc: 分配新内存 → 逐节复制 → 解析导入 → 执行

  2. 风险检测 (pe2shc 转换时输出 [WARN]):
     - /GS Security Cookie
     - SEH handler table
     - Control Flow Guard
     - Delay-load imports
     - .bss 未初始化段（自动零填充）

  3. 向后兼容:
     有 .reloc 的 PE 走原有加载路径，行为不变。







 stub2/stub32.bin 和 stub2/stub64.bin 是 Loader stub 的编译产物。

  干什么用的

  ┌──────────────────────────────────────────────┐
  │  pe2shc.exe 在处理输入 PE 时：               │
  │                                              │
  │  1. 读入 test.exe                            │
  │  2. 把 test.exe 复制到新缓冲区               │
  │  3. 把 stub64.bin 追加到 test.exe 的末尾     │
  │  4. 修改 test.exe 的头部，写入重定向代码     │
  │     让入口点跳转到追加的 stub 位置执行       │
  │  5. 输出 test.shc.exe                        │
  └──────────────────────────────────────────────┘

  所以 .shc.exe 的文件结构是：

  ┌─────────────────────────────┐
  │  test.exe 原始 PE 数据      │
  │  （头部已被重定向代码修改） │
  ├─────────────────────────────┤
  │  stub64.bin                 │  ← 加载器代码
  │  （被 .rc 资源嵌入 pe2shc） │
  └─────────────────────────────┘

  运行时流程：

  Windows 加载 test.shc.exe → 调用入口点
      → 入口点已被重定向到 stub 位置
      → stub 开始执行:
          用 PEB 找 kernel32 → 解析 LoadLibraryA/GetProcAddress
          → 检查 PE 头的 min_hdr.load_status == LDS_CLEAN
          → 有 .reloc → 原地重定位 + 导入 + 执行
          → 无 .reloc → In-Place 或 VirtualAlloc + 复制 + 导入 + 执行
          → 调用原始 test.exe 的入口点

  怎么来的

  这两文件是 loader_v2/peloader.cpp 经过编译流水线生成的：

  peloader.cpp
    → cl /c /GS- /FA /O1      (MASM 列表)
    → masm_shc.exe             (位置无关 shellcode asm)
    → ml64 / link              (汇编链接成 PE)
    → extract_text.py          (提取 .text 段 → .bin)

  pe2shc/resource2.rc 中通过 RCDATA 把它们嵌进 pe2shc.exe：

  STUB32  RCDATA  "stub2\stub32.bin"
  STUB64  RCDATA  "stub2\stub64.bin"