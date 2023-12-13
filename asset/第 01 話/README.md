# 【第 01 話】Kernel 層概觀

## 文章大綱
這篇會介紹這個系列的文章所專注要說明的範圍，以及學習 Windows Kernel 的重要性，還有在讀完所有文章後預期大家會學到的知識與技能。


## Ring0、Ring3
在 Windows 中，Ring3 是應用層，Ring0 是 Kernel 層，Ring1、Ring2 大部分都處於保留的狀態。

![](Ring.png)

其實在 Ring0 之下還有 VM 層的 Ring -1 與最近比較新的研究提出在硬體層的 Ring -2，不過這個系列的文章還是會專注說明 Ring3 與 Ring0 的部分。


## Kernel 安全影響
一般使用者在操作應用程式（Process）、檔案（File）、登錄碼（Registry）、網路（Network），在作業系統提供的桌面上執行程式、開啟檔案、上網等等，都是從 Ring3 操作。而在 Ring0 也有各種類型的驅動程式運行著，它們除了可以控制 Ring0 的記憶體之外，Ring3 的各種操作也做得到。因此如果驅動程式有漏洞，造成的後果也十分嚴重。

![](kernel.png)

這個系列的文章主要針對上圖左下角的 WDM（Windows Driver Model）類型的驅動程式。因為這個類型的驅動程式在市面上目前佔多數，以學習 Kernel 層安全來說我認為也是比較容易入手的。

## 預期所學
這個系列的文章將圍繞 Windows Kernel 的漏洞及其利用，從最基礎的開發與除錯環境建置和工具使用到找漏洞並且寫攻擊腳本。

以下是這個系列的目錄，所有文章與講解的程式都會備份在我的專案 [zeze-zeze/2023iThome](https://github.com/zeze-zeze/2023iThome)。有任何問題、發現錯字（typo）、程式有誤，或是任何建議都可以在留言區提出，也可以在 GitHub 發 Issue 或是發 PR 成為 Contributor，我有看到且有空就會回覆。另外如果覺得我寫得不錯也請多多 Like 我的文章和幫我的 GitHub 專案按 Star，我看到了會很開心:D

- [【第 01 話】Kernel 層概觀](/asset/第%2001%20話)
- [【第 02 話】開發、測試與除錯環境建置](/asset/第%2002%20話)
- [【第 03 話】簡單的 WDM 驅動程式](/asset/第%2003%20話)
- [【第 04 話】WinDbg 竄改 EPROCESS Token](/asset/第%2004%20話)
- [【第 05 話】傳送 IRP 到驅動程式](/asset/第%2005%20話)
- [【第 06 話】IOCTL 與驅動程式溝通－實作竄改 EPROCESS TOKEN](/asset/第%2006%20話)
- [【第 07 話】逆向分析 WDM 驅動程式](/asset/第%2007%20話)
- [【第 08 話】攻擊自己寫的驅動程式－Null Pointer Dereference](/asset/第%2008%20話)
- [【第 09 話】CVE-2023-1643 研究－Null Pointer Dereference](/asset/第%2009%20話)
- [【第 10 話】寫 Shellcode 竄改 EPROCESS Token](/asset/第%2010%20話)
- [【第 11 話】Capcom.sys 研究－任意程式執行](/asset/第%2011%20話)
- [【第 12 話】CVE-2020-17382 研究－Buffer Overflow（上）](/asset/第%2012%20話)
- [【第 13 話】CVE-2020-17382 研究－Buffer Overflow（下）](/asset/第%2013%20話)
- [【第 14 話】CVE-2019-16098 研究－任意讀寫虛擬記憶體](/asset/第%2014%20話)
- [【第 15 話】簡單的 Kernel Fuzzer](/asset/第%2015%20話)
- [【第 16 話】CVE-2023-1486 研究－任意刪除檔案](/asset/第%2016%20話)
- [【第 17 話】從物理記憶體竄改 EPROCESS Token](/asset/第%2017%20話)
- [【第 18 話】CVE-2023-1679 研究－任意讀寫物理記憶體](/asset/第%2018%20話)
- [【第 19 話】CVE-2023-1489 研究－任意 wrmsr 到任意執行](/asset/第%2019%20話)
- [【第 20 話】BYOVD 攻擊](/asset/第%2020%20話)
- [【第 21 話】驅動程式數位簽章](/asset/第%2021%20話)
- [【第 22 話】繞過數位簽章](/asset/第%2022%20話)
- [【第 23 話】DKOM 隱藏 Process（上）](/asset/第%2023%20話)
- [【第 24 話】DKOM 隱藏 Process（中）](/asset/第%2024%20話)
- [【第 25 話】DKOM 隱藏 Process（下）](/asset/第%2025%20話)
- [【第 26 話】Kernel Callback 隱藏 Registry](/asset/第%2026%20話)
- [【第 27 話】Minifilter 保護檔案](/asset/第%2027%20話)
- [【第 28 話】Minifilter 隱藏檔案](/asset/第%2028%20話)
- [【第 29 話】WFP 監控流量](/asset/第%2029%20話)
- [【第 30 話】WFP 隱藏流量](/asset/第%2030%20話)


## 資安宣導
文章的內容主要來自網路上蒐集的專案、部落格、研討會簡報等等，還有我自己找到的漏洞與寫成的攻擊腳本。所有文章皆是以教育為目的，希望大家可以透過這些文章更容易理解系統底層的知識，切勿應用於違法行為。


## 參考資料
- [分級保護域](https://zh.wikipedia.org/zh-tw/%E5%88%86%E7%B4%9A%E4%BF%9D%E8%AD%B7%E5%9F%9F)
- [xoreaxeaxeax/sinkhole](https://github.com/xoreaxeaxeax/sinkhole)