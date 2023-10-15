# 【第 24 話】DKOM 隱藏 Process（中）

## 文章大綱
在[【第 23 話】DKOM 隱藏 Process（上）](/asset/第%2023%20話)了解 DKOM 的原理，這篇要帶大家用 WinDbg 實作，利用 WinDbg 竄改結構達到隱藏 Process 的效果。


## WinDbg 操作
跟[【第 21 話】驅動程式數位簽章](/asset/第%2021%20話)一樣，開啟 VM 的 Local Debug 模式，重新開機後執行 Windbg。要用 Local Debug 而不是用 VirtualKD-Redux 的原因是 VirtualKD-Redux 會幫我們開測試模式，PatchGuard 就不會偵測了。

在桌面開啟 cmd，首先取得它的 EPROCESS 位址 `ffff9b8efb1d95c0`。
```
kd> !process 0 0 cmd.exe
PROCESS ffff9b8efb1d95c0
    SessionId: 1  Cid: 0bc8    Peb: 46b6287000  ParentCid: 0bdc
    DirBase: 02c63000  ObjectTable: ffffab822b466a80  HandleCount:  40.
    Image: cmd.exe
```

接下來跟講解原理的步驟相似，不過要把概念更具體說明。

- ActiveProcessLinks 斷鏈
- HandleTableList 斷鏈
- ProcessListEntry 斷鏈
- PspCidTable 清零


### ActiveProcessLinks 斷鏈
從 EPROCESS 中找出 ActiveProcessLinks，點擊輸出的 ActiveProcessLinks，可以看到 LIST_ENTRY 結構中的 Flink `0xffff9b8efb08e8a8` 和 Blink `0xffff9b8ef94de368`。
```
kd> dt nt!_EPROCESS ffff9b8efb1d95c0 ActiveProcessLinks
   +0x2e8 ActiveProcessLinks : _LIST_ENTRY [ 0xffff9b8e`fb08e8a8 - 0xffff9b8e`f94de368 ]
   
kd> dx -id 0,0,ffff9b8ef8875040 -r1 (*((ntkrnlmp!_LIST_ENTRY *)0xffff9b8efb1d98a8))
(*((ntkrnlmp!_LIST_ENTRY *)0xffff9b8efb1d98a8))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0xffff9b8efb08e8a8 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0xffff9b8ef94de368 [Type: _LIST_ENTRY *]
```

有了 Flink 和 Blink 後，接下來就是斷鏈。

```
kd> eq 0xffff9b8efb08e8a8+8 0xffff9b8ef94de368 
kd> eq 0xffff9b8ef94de368 0xffff9b8efb08e8a8 
```

現在開啟 Process Explorer 查看，可以發現已經找不到剛剛執行的 cmd 了，不過只改這樣會讓系統不穩定。


### HandleTableList 斷鏈
從 EPROCESS 中找出 ObjectTable，點擊輸出的 ObjectTable，在 Offset 0x18 的位址可以看到要改的目標 HandleTableList。
```
kd> dt nt!_EPROCESS ffff9b8efb1d95c0 ObjectTable
   +0x418 ObjectTable : 0xffffab82`2b466a80 _HANDLE_TABLE
   
kd> dx -id 0,0,ffff9b8efa1755c0 -r1 ((ntkrnlmp!_HANDLE_TABLE *)0xffffab822b466a80)
((ntkrnlmp!_HANDLE_TABLE *)0xffffab822b466a80)                 : 0xffffab822b466a80 [Type: _HANDLE_TABLE *]
    [+0x000] NextHandleNeedingPool : 0x400 [Type: unsigned long]
    ...
    [+0x018] HandleTableList  [Type: _LIST_ENTRY]
    ...
    [+0x060] DebugInfo        : 0x0 [Type: _HANDLE_TRACE_DEBUG_INFO *]
```

再點擊 HandleTableList 就能看到 `LIST_ENTRY` 結構的 Flink `0xffffab822b609218` 和 Blink `0xffffab822e518258`。

```
kd> dx -id 0,0,ffff9b8efa1755c0 -r1 (*((ntkrnlmp!_LIST_ENTRY *)0xffffab822b466a98))
(*((ntkrnlmp!_LIST_ENTRY *)0xffffab822b466a98))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0xffffab822b609218 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0xffffab822e518258 [Type: _LIST_ENTRY *]
```

跟 ActiveProcessLinks 一樣，將 HandleTableList 斷鏈。

```
kd> eq 0xffffab822b609218+8 0xffffab822e518258 
kd> eq 0xffffab822e518258 0xffffab822b609218  
```


### ProcessListEntry 斷鏈
從 EPROCESS 中找出 Pcb，點擊輸出的 Pcb，在 Offset 0x240 的位址可以看到要改的目標 ProcessListEntry。
```
kd> dt nt!_EPROCESS ffff9b8efb1d95c0 Pcb
   +0x000 Pcb : _KPROCESS
   
kd> dx -id 0,0,ffff9b8efa1755c0 -r1 (*((ntkrnlmp!_KPROCESS *)0xffff9b8efb1d95c0))
(*((ntkrnlmp!_KPROCESS *)0xffff9b8efb1d95c0))                 [Type: _KPROCESS]
   [+0x000] Header           [Type: _DISPATCHER_HEADER]
   ...
   [+0x240] ProcessListEntry [Type: _LIST_ENTRY]
   ...
   [+0x2d0] SecureState      [Type: <unnamed-tag>]
```

再點擊 ProcessListEntry 就能看到 LIST_ENTRY 結構的 Flink `0xffff9b8efb08e800` 和 Blink `0xffff9b8ef94de2c0`。
```
kd> dx -id 0,0,ffff9b8efa1755c0 -r1 (*((ntkrnlmp!_LIST_ENTRY *)0xffff9b8efb1d9800))
(*((ntkrnlmp!_LIST_ENTRY *)0xffff9b8efb1d9800))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0xffff9b8efb08e800 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0xffff9b8ef94de2c0 [Type: _LIST_ENTRY *]
```

跟 ActiveProcessLinks 和 HandleTableList 一樣，將 ProcessListEntry 斷鏈。

```
kd> eq 0xffff9b8efb08e800+8 0xffff9b8ef94de2c0 
kd> eq 0xffff9b8ef94de2c0 0xffff9b8efb08e800  
```


### PspCidTable 清零
在[【第 23 話】DKOM 隱藏 Process（上）](/asset/第%2023%20話)有提到 PspCidTable 可以從 `PsLookupProcessByProcessId` 函數呼叫的 `PspReferenceCidTableEntry` 中取得。

在 WinDbg 裡反組譯 `PsLookupProcessByProcessId`，下面有一條 Instruction 在呼叫 `PspReferenceCidTableEntry`。

```
kd> u PsLookupProcessByProcessId L10
nt!PsLookupProcessByProcessId:
fffff800`3295ead0 48895c2408      mov     qword ptr [rsp+8],rbx
...
fffff800`3295eafa e8412afcff      call    nt!PspReferenceCidTableEntry (fffff800`32921540)
...
```

再反組譯 `PspReferenceCidTableEntry` 就找到 PspCidTable 了。

```
kd> u PspReferenceCidTableEntry
nt!PspReferenceCidTableEntry:
fffff800`32921540 48896c2420      mov     qword ptr [rsp+20h],rbp
...
fffff800`3292154a 488b05afbcedff  mov     rax,qword ptr [nt!PspCidTable (fffff800`327fd200)]
...
```

不過因為 PspCidTable 在 WinDbg 有 Symbol，所以其實可以直接用名字訪問它，輸出的結果是 `ffffab8227e17e00`。而這個位址所存放結構跟 HandleTableList 一樣是 HANDLE_TABLE，但是這裡的目標是 TableCode `0xffffab822a674001`。

```
kd> dq PspCidTable L1
fffff800`327fd200  ffffab82`27e17e00

kd> dt _HANDLE_TABLE ffffab82`27e17e00
nt!_HANDLE_TABLE
   +0x000 NextHandleNeedingPool : 0x1800
   ...
   +0x008 TableCode        : 0xffffab82`2a674001
   ...
   +0x060 DebugInfo        : (null) 
```

這個 TableCode 最後 2 bits 是 1，所以是個二級指標，也就是說裡面存的是許多個一級指標。下面輸出的每個一級指標又各存放著 256 個 EPROCESS 位址。

```
kd> dq 0xffffab82`2a674000
ffffab82`2a674000  ffffab82`27e1a000 ffffab82`2a677000
ffffab82`2a674010  ffffab82`2c708000 ffffab82`29982000
ffffab82`2a674020  ffffab82`29f45000 ffffab82`2b89b000
...
```

以我實測的狀況而言，cmd 的 pid 是 3016，第一個一級指標存的是 pid 0～1024，第二個是 pid 1024～2048，所以 pid 3016 理論上會在第三個一級指標 `ffffab822c708000`。那 pid 3016 就會是第三個一級指標中的第 243 項。
```
x = (3016 - 2048) / 4 + 1 = 243
```

所以列舉第三個一級指標的所有 EPROCESS，第 243 項就是 cmd 的 EPROCESS。拿到的值是 `9b8efb1d95c0e033`，但前面用 `!process` 指令取得 cmd 的 EPROCESS 應該是 `ffff9b8efb1d95c0` 才對，為什麼不同呢？

```
kd> dq ffffab822c708000 L200
...
ffffab82`2c708f20  9b8efb1d`95c0e033 00000000`00000000
...
```

因為在不同版本的 Windows，取得的值要經過不同的解碼才會是 EPROCESS 位址。
- Win7：`value & 0xfffffffffffffff0`
- Win8：`(value >> 13) & 0xfffffffffffffff0`
- Win10：`(value >> 0x10) & 0xfffffffffffffff0`

所以把取得的 `9b8efb1d95c0e033` 在我們的環境 Windows 10 1709 轉換後就是 cmd 的 EPROCESS `ffff9b8efb1d95c0`。


## 參考資料
- [Manipulating ActiveProcessLinks to Hide Processes in Userland](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/manipulating-activeprocesslinks-to-unlink-processes-in-userland)
- [[原创]某地牛逼哄哄的内部辅X,通过进程断链让DWM复活](https://bbs.kanxue.com/thread-270932.htm)
- [zeze-zeze/GhostProcess](https://github.com/zeze-zeze/GhostProcess)
- [GHOST PROCESS - HIDE PROCESS IN KERNEL EVADING PATCHGUARD](https://vxcon.hk/)
- [EPROCESS](https://www.nirsoft.net/kernel_struct/vista/EPROCESS.html)