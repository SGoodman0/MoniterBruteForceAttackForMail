說明:
-------
本程式對密碼嘗試進行偵測並以iptables進行防護

僅針對postfix與dovecot提供之mail service  <br />
其他相關套件等並未測試，但驗證之回傳訊息大都為同一標準  <br />
理論上應可使用，但須更改syslog之設定路徑參數等


環境:
-------
Python Version : 2.7.13  <br />
Postfix需開啟驗證功能(預設為不開啟)  <br />
需下載並安裝scapy函式庫


使用方法:
-----------
1. Get this code.
2. 在同目錄下建立一檔案為passlist.txt
3. 將白名單之IP輸入至該檔案
4. 注意權限問題與路徑即可
5. 手動執行或寫入開機執行即可，但應先測試
