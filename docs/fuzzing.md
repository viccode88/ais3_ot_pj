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

二十二種策略涵蓋 quantity 邊界、bit/byte flip、MBAP length、function code、transaction ID、
Unit ID、語意不一致、隨機 byte replacement、huge-payload，九種協定語意策略
（protocol-id、address-wrap、truncated-mbap、concatenated-adu、pdu-mismatch、
exception-shape、mei-subtype、rtu-over-tcp、fill），以及三種會話層策略
（fragmented-send、repeat-storm、session-sequence）。相同 seed、策略順序和案例數
會產生相同 request，方便重現。

會話層策略由案例上的 `send_plan` 驅動：executor 在單一 TCP 連線內分段、重發或依序送出
多個 payload，逐步證據保存在案例的 `execution` 欄位。這對應真實 OT 環境的長連線與
partial frame 場景（例如 CVE-2025-53476 類的連線持有問題）。

`huge-payload` 產生舊腳本的 FC16 Write Multiple Registers malformed payload：quantity
200..2000、實際 body 為 `quantity * 2` bytes、1-byte `byte_count` 依舊 wrap，MBAP length 宣告
完整 oversized PDU。這是用來測試虛擬環境解析與資源處理可靠性的 write-function、oversized
ADU 輸入，不屬於任何 vulnerability case。

## 即時終端輸出

使用 `fuzz --execute` 時，CLI 會在每個案例送出前顯示 `TX request-type`，收到結果後顯示
`RX response-type`。類型分別從突變後的實際 request 與目標實際回傳資料解碼，因此不會把
基準 FC03 硬套到所有案例或回應。

逐案資訊寫到 stderr，stdout 仍只包含最後的 JSON 摘要，`--output` 則保存完整案例報告。
目標未回傳封包時會顯示 `response-type=no-packet`，並以 `status` 區分 timeout、
`connection-refused` 或其他 transport error。沒有 `--execute` 的離線模式不會顯示 TX/RX。

加 `--health-check-interval N` 可在每傳送 N 個案例後插入一次已知正常的 FC03 health
probe：目標若在 fuzz 中途退化，report 中該案例的 `health_after` 與摘要的
`health_failures` 能精確定位最後一根稻草，而不是跑完才發現全部 timeout。

這個工具服務於完全虛擬環境的可靠性測試，因此傳輸邊界刻意不做 read-only 或 framing
檢查：過嚴的安全邊界會讓測試低弱且無效，反而讓問題流入生產環境。寫入功能碼、未知功能碼、
串接 ADU、非 MEI 0x0E 的 FC43、`length` strategy 的截斷/延伸 PDU 和 oversized payload 都會
實際送出。只有空 payload 無法傳輸，會以 `blocked-by-safety-policy` 留在 report。這表示測試
目標必須是可拋棄的虛擬環境，絕不能指向生產設備。

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
必須先檢查輸出，再決定是否重播。`replay` 與 fuzz 使用相同的傳輸邊界：寫入、未知或畸形
payload 都會重送到 report 記錄的虛擬環境目標，只保留 50 requests/second 上限。
expert-level raw `send` 也會原樣傳送提供的 ADU。
