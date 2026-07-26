# Fuzzing 原則與結果判讀

實際指令、參數與案例格式請先讀 [`modbus-cli.md`](modbus-cli.md#12-fuzz-corpusfuzz)。

## 安全預設

`fuzz` 預設只在本機產生 deterministic corpus。只有顯式加入 `--execute` 才會傳送。即使
不傳送，target 仍必須能解析且位於允許的實驗室私網，因為 target 會被保存到 report。

Target 可直接由 `--target/--port` 指定，也可用 `--scan-report` 從整合掃描結果選取。後者
只接受唯一一個已由有效 Modbus MBAP 回應確認、且標記為 fuzz-eligible 的開放埠；報告的
resolved address 會重新套用私網 policy。Port number 本身永遠不算協定確認。

只有 `--scan-report --execute` 會在 fuzz cases 之外額外送出一個相同 Unit ID 的唯讀 FC03
protocol-correlation preflight。合法的正常或 exception response 都可通過，所以它只重新
確認 endpoint 與 request/response correlation，不代表應用程式健康或位址 0 可讀。成功後
工具會等待一個設定的 fuzz interval，再送第一個 case；`--requests` 只計算 fuzz cases。

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

所有 mutation 在傳輸邊界會再檢查一次實際 function code。目前只允許明確唯讀的
FC01、02、03、04、07、11、12、17、20、24、43；寫入與未知功能碼會顯示 `BLOCKED` 並以
`blocked-by-safety-policy` 留在 report，TCP socket 不會建立。這項檢查針對突變後 payload，
不能由「baseline 原本是 FC03」取代。傳輸邊界只允許單一、長度完全一致的 MBAP ADU；
FC43 也只允許 MEI 0x0E Read Device Identification。`length` strategy 的畸形 framing 可
保留作離線 corpus，但主動執行時會被封鎖。

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
必須先檢查輸出，再決定是否重播。`replay` 也會套用相同唯讀 allowlist、單一 ADU framing
檢查與 50 requests/second 上限，不會把 report 中標為 blocked 的寫入/未知功能碼案例送出。
這些 fuzz/replay 安全邊界不套用到 expert-level raw `send`，後者會原樣傳送提供的 ADU。
