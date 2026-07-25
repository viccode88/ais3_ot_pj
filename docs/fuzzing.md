# Fuzzing 原則與結果判讀

實際指令、參數與案例格式請先讀 [`modbus-cli.md`](modbus-cli.md#12-fuzz-corpusfuzz)。

## 安全預設

`fuzz` 預設只在本機產生 deterministic corpus。只有顯式加入 `--execute` 才會傳送。即使
不傳送，target 仍必須能解析且位於允許的實驗室私網，因為 target 會被保存到 report。

執行前應先：

1. 對目標建立快照或確認可復原方式。
2. 用已知正常的唯讀 request 建立 health baseline。
3. 離線產生並人工檢查 corpus。
4. 從少量案例與低速率開始。
5. 同時保存 CLI JSON、PCAP、服務日誌和主控台狀態。

## 策略

九種策略涵蓋 quantity 邊界、bit/byte flip、MBAP length、function code、transaction ID、
Unit ID、語意不一致和隨機 byte replacement。相同 seed、策略順序和案例數會產生相同
request，方便重現。

## 即時終端輸出

使用 `fuzz --execute` 時，CLI 會在每個案例送出前顯示 `TX request-type`，收到結果後顯示
`RX response-type`。類型分別從突變後的實際 request 與目標實際回傳資料解碼，因此不會把
基準 FC03 硬套到所有案例或回應。

逐案資訊寫到 stderr，stdout 仍只包含最後的 JSON 摘要，`--output` 則保存完整案例報告。
目標未回傳封包時會顯示 `response-type=no-packet`，並以 `status` 區分 timeout、
`connection-refused` 或其他 transport error。沒有 `--execute` 的離線模式不會顯示 TX/RX。

## 分類不是漏洞結論

一次 timeout 只分類為 `possible-service-degradation`，不能宣稱 crash 或 CVE。transport
錯誤只表示該次連線異常；parser warning 也只表示 response 結構值得調查。

可疑案例至少應完成：

1. 停止 fuzz。
2. 重跑使用者事先選定的正常 health request。
3. 查看服務、作業系統和 PLC application 日誌。
4. 在已還原的環境中重播單一案例。
5. 比對 response、時間、服務狀態和 process restart 等獨立證據。

`minimize` 目前只做結構裁切，不是完整 delta-debugging，也不會自動 replay 驗證。操作員
必須先檢查輸出，再決定是否重播。
