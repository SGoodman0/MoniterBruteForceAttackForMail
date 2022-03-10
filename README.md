簡介：
-------
基本上是因為自己架設過一台 Mail Server，觀察 syslog 時發現有許多帳號密碼錯誤且來源不明的紀錄。

故設計該程式處理。

說明：
-------
本程式對 Mail 的暴力解攻擊進行偵測，

基本上是透過 syslog 去偵測，滿足條件時，以 iptables 進行後處理之防護。

僅針對postfix與dovecot提供之mail service，

其他相關套件等並未測試，但透過 syslog 與正規表示式之修改。

理論上應可使用。


環境：
-------
Python Version : 2.7.13 

Postfix 需開啟驗證功能(預設為不開啟)。

需下載並安裝scapy函式庫。

使用方法：
-----------
1. Get this code.
2. 在同目錄下建立一檔案為passlist.txt
3. 將白名單之IP輸入至該檔案
4. 注意權限問題與路徑即可
5. 手動執行或寫入開機執行即可，但應先測試
