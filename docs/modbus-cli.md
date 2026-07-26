# `modbus-cli` 使用手冊

本文件說明 `modbus-cli` 0.2.x 的實際操作方式。所有位址、功能碼和限制都以目前程式行為
為準。

## 1. 使用前準備

請先完成以下檢查：

1. 目標是可丟棄的 PLC、模擬器或測試 VM。
2. 測試端與目標位於 host-only、獨立 VLAN 或同等隔離網路。
3. 你知道確切的目標 IP、Modbus TCP port、Unit ID 和可安全讀取的位址。
4. 目標狀態已有快照或可復原方式。
5. fuzz 前已先用單一唯讀 request 確認服務正常。

工具目前只支援 IPv4 Modbus TCP。它不支援 Modbus RTU、ASCII、TLS 或網段掃描；每個
request 會建立新的 TCP 連線。

## 2. 指令結構

```text
modbus-cli <command> [command options]
```

查詢所有 command：

```bash
modbus-cli --help
```

查詢特定 command：

```bash
modbus-cli build --help
modbus-cli fuzz --help
```

若沒有 console script，也可使用：

```bash
python -m modbus_cli <command> [command options]
```

安裝套件時也會建立 `mbfuzz`。它是 `modbus-cli` 的**完整別名**，不是只能執行 fuzz 的精簡
版本；下列兩行會進入完全相同的 parser 和執行路徑：

```bash
modbus-cli build --function 3
mbfuzz build --function 3
```

因此本文件所有 `modbus-cli ...` 範例都可以把第一個單字替換成 `mbfuzz`。為了讓說明一致，
後續仍統一使用 `modbus-cli`。

指令總覽：

| 指令 | 用途 | 網路/檔案副作用 |
| --- | --- | --- |
| `version` | 顯示 JSON 版本資訊 | 無 |
| `info` | 顯示環境、策略與插件資訊 | 載入插件 metadata |
| `scan` | 掃描並辨識 PLC/ICS TCP 服務 | 建立 TCP 連線並執行所選安全 probe；可寫 report |
| `build` | 建立 Modbus TCP ADU | 無；輸出到 stdout |
| `decode` | 解析 hex 或 binary ADU | 只讀指定檔案 |
| `read` | 傳送 FC01–04 唯讀 request | 立即建立 TCP 連線 |
| `probe` | 傳送最小 FC03 health request | 立即建立 TCP 連線 |
| `send` | 原樣傳送自訂 ADU | 立即建立 TCP 連線 |
| `write` | 建立寫入 request preview | 目前只有 `--dry-run` 可成功，不連線 |
| `fuzz` | 產生或執行 deterministic fuzz cases | 預設寫 report；`--execute` 才連線 |
| `replay` | 重送 report 的第一筆 case | 立即建立 TCP 連線 |
| `minimize` | 裁切 report 的第一筆 case | 寫入 `*-minimized.json` |
| `config` | 建立、顯示或驗證設定檔 | `init` 會寫檔 |
| `plugins` | 列出或驗證插件 | `info`/`validate` 會載入插件 |

全域選項：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `-h`, `--help` | 否 | 關閉 | 顯示頂層說明並結束 |
| `--version` | 否 | 關閉 | 直接輸出版本字串並結束；不需要再指定子指令 |

## 3. 共用網路參數

`read`、`send`、`write`、`probe` 和直接指定 target 的 `fuzz` 使用以下共用參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `--target HOST` | 是 | 無 | 單一 IPv4 或可解析為 IPv4 的 hostname |
| `--port PORT` | 否 | `502` | Modbus TCP port，範圍 1–65535 |
| `--timeout SEC` | 否 | `1.5` | TCP connect/read timeout，必須大於 0 |

部分指令另有 `--unit-id`，預設為 `1`。

預設只允許 loopback 和 RFC1918 私有位址。公網、IPv6、無法解析的 hostname 都會被拒絕。
hostname 的 DNS 結果若不是允許的私有 IPv4，也會被拒絕。

## 3A. PLC/ICS 服務掃描：`scan`

完整的端口 catalog、結果欄位、非標準埠、scan report 交接、主動執行與疑難排解，請見
[`scan-to-fuzz.md`](scan-to-fuzz.md)。

**用途與副作用：**對單一已授權的私有 IPv4 掃描常見 PLC/ICS TCP 埠，再對已開放的指定
角色埠做安全的 Modbus、EtherNet/IP、OPC UA、HTTP/TLS 等協定 probe。掃描一定會建立網路
連線；`--output` 只是額外保存結果，不會把掃描變成離線操作。

```bash
modbus-cli scan \
  --target 192.168.56.10 \
  --profile safe \
  --max-layer 2 \
  --ports 22,80,102,502,1217,4840,8000-8010,11740,44818 \
  --format text
```

重要參數：

| 參數 | 預設 | 意義 |
| --- | --- | --- |
| `--target HOST` | 必填 | 私有/loopback IPv4 或可解析 hostname |
| `--profile` | `safe` | `safe`、`standard` 或 `lab` 的探測節奏/預算 |
| `--max-layer` | `2` | 最高主動探測層，1–4 |
| `--ports SPEC` | 無 | 額外 TCP 逗號清單/範圍；最多展開 1024 埠 |
| `--modbus-port` | `502` | 要做 Modbus 上層確認的角色埠 |
| `--v3-http-port` / `--v4-https-port` | `8080` / `8443` | OpenPLC Web 候選角色埠 |
| `--enip-port` / `--opcua-port` / `--dnp3-port` | 協定標準值 | 其他工控協定角色埠 |
| `--packet-budget` | profile 預設 | 掃描與上層 probe 共用的硬性 network-action 上限 |
| `--format` | `json` | `json`、`text`、`csv` 或 `sarif` |
| `--output PATH` | stdout | 將選定格式寫到檔案，stdout 改輸出精簡摘要 |

結構化 JSON 以 `port_findings` 列出 `state`、`service_id/service_name`、`plc_relevance`、
`identification`、證據與 `fuzz_eligible`。`HIGH`/`plc_relevance=high` 是 PLC 關聯標記，
不是確認結果；只有有效上層回應才是 `identification=confirmed`。`port_summary` 直接列出
高相關開放埠、已確認服務與可交給 fuzz 的候選。Action budget 不足而尚未探測的埠是
`state=not-scanned`，不會與實際探測失敗的 `unavailable` 混在一起；
`port_summary.scan_complete` 則獨立表示整體掃描與上層 probe 是否在 network-action budget
內完成；
即使所有 TCP 埠已掃完，上層 probe 中途耗盡 budget 仍會是 `false`。自訂角色埠與
`--ports` 指定埠會排在預設 catalog 埠前面，讓較小的 action budget 優先處理操作員指定
範圍。

`--packet-budget` 是沿用的 CLI 名稱：scheduler 每執行一次 connect、HTTP request、
Modbus exchange 等高階 network action 就計數一次。它不是 wire-packet cap；一個 action
可能產生多個 TCP/IP packets。JSON 的 `packets_sent` 欄位同樣是 action 計數。

角色埠選項只移動該協定的主動 probe，不會刪除標準 catalog 埠。例如
`--modbus-port 1502` 會在 1502 執行 Modbus 確認，但 502 仍保留 TCP connect 與
Modbus port-hint。

若要交給 fuzz，必須保存 **JSON**：

```bash
modbus-cli scan \
  --target 192.168.56.10 \
  --modbus-port 1502 \
  --output artifacts/scan-report.json
```

## 4. Modbus 位址怎麼填

`--address` 直接寫入 Modbus PDU，是 `0..65535` 的零起算 protocol address。

某些設備手冊使用參照編號，例如：

| 手冊常見寫法 | 類型 | 常見的 protocol address |
| --- | --- | --- |
| `00001` | Coil | `0` |
| `10001` | Discrete input | `0` |
| `30001` | Input register | `0` |
| `40001` | Holding register | `0` |

這個換算只是常見慣例。有些廠商文件已經直接使用零起算位址，所以不能看到 `40001` 就一律
減去 40001。請先核對設備手冊或已知正常的 client。

## 5. 功能碼與數值限制

| 十進位功能碼 | 名稱 | `build` 的必要資料 | 限制 |
| --- | --- | --- | --- |
| `1` | Read Coils | `--address --quantity` | quantity 1–2000 |
| `2` | Read Discrete Inputs | `--address --quantity` | quantity 1–2000 |
| `3` | Read Holding Registers | `--address --quantity` | quantity 1–125 |
| `4` | Read Input Registers | `--address --quantity` | quantity 1–125 |
| `5` | Write Single Coil | `--address --values` | 單一值 `0` 或 `1` |
| `6` | Write Single Register | `--address --values` | 單一 uint16 |
| `15` | Write Multiple Coils | `--address --values` | 1–1968 個值 |
| `16` | Write Multiple Registers | `--address --values` | 1–123 個 uint16 |

`--values` 以逗號分隔，接受十進位或 `0x` 開頭的十六進位：

```text
--values 1
--values 100,200,300
--values 0x0001,0x1234,0xFFFF
```

## 6. 離線建立封包：`build`

**用途與副作用：**依參數在本機建立一個 Modbus TCP ADU，不解析 target、不開啟網路連線，
也不寫入檔案；只有使用者自行以 shell redirect 保存輸出時才會產生檔案。

基本語法：

```bash
modbus-cli build \
  --function FUNCTION \
  [--address ADDRESS] \
  [--quantity QUANTITY] \
  [--values CSV] \
  [--transaction-id ID] \
  [--protocol-id ID] \
  [--unit-id ID] \
  [--output text|hex|json|binary]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `--function FUNCTION` | 是 | 無 | 十進位功能碼，wire 欄位必須在 0–255；常用且具結構化編碼的功能碼見上一節 |
| `--address ADDRESS` | 否 | `0` | 零起算 protocol address，範圍 0–65535 |
| `--quantity QUANTITY` | 否 | `1` | 讀取數量；允許範圍依功能碼而異 |
| `--values CSV` | 否 | 無 | 寫入值，使用逗號分隔；每個值接受十進位或 `0x` 前綴 |
| `--transaction-id ID` | 否 | `1` | MBAP transaction ID，必須可放入 uint16 |
| `--protocol-id ID` | 否 | `0` | MBAP protocol ID，標準 Modbus TCP 使用 0，必須可放入 uint16 |
| `--unit-id ID` | 否 | `1` | Unit ID，必須可放入 uint8 |
| `--output FORMAT` | 否 | `text` | `text`、`hex`、`json` 或 `binary` |

### 詳細範例

建立 transaction ID 1、Unit ID 1，從 address 0 讀取 10 個 holding registers 的 FC03
request：

```bash
modbus-cli build \
  --transaction-id 1 \
  --unit-id 1 \
  --function 3 \
  --address 0 \
  --quantity 10 \
  --output json
```

### 輸出與副作用

輸出中的：

- `hex` 是完整 Modbus TCP ADU。
- `packet_length` 是 byte 數。
- `packet` 是重新解析後的欄位。
- `warnings` 為空表示結構上沒有發現問題，不代表目標一定支援該位址。

目前 `--output text` 和 `--output json` 都會輸出相同的 pretty-printed JSON；`hex` 只輸出
一行十六進位，`binary` 則直接把 raw bytes 寫到 stdout。

只顯示 hex：

```bash
modbus-cli build --function 3 --address 0 --quantity 10 --output hex
```

輸出 raw binary：

```bash
modbus-cli build --function 3 --address 0 --quantity 10 --output binary > request.bin
```

`build` 永遠不會連線。即使建立的是寫入功能碼，也只會在 stdout 產生封包。

## 7. 離線解析封包：`decode`

**用途與副作用：**在本機以 best-effort 方式解析一個 Modbus TCP ADU。它不連線、不傳送
封包，也不修改來源檔案。

語法：

```bash
modbus-cli decode \
  (--hex HEX | --file FILE) \
  [--output text|json]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `--hex HEX` | 與 `--file` 二選一 | 無 | 完整 ADU 的十六進位字串 |
| `--file FILE` | 與 `--hex` 二選一 | 無 | 內含 raw bytes 的 binary 檔案路徑 |
| `--output FORMAT` | 否 | `text` | `text` 或 `json`；目前兩者都輸出相同的 pretty-printed JSON |

### 詳細範例

解析 hex：

```bash
modbus-cli decode --hex 00010000000601030000000A
```

解析 raw binary：

```bash
modbus-cli decode --file request.bin
```

`--hex` 和 `--file` 只能選一個。`--file` 必須是 binary；若檔案內容是字串
`000100...`，請改用 `--hex`。

### 輸出與副作用

目前 `--output text` 和 `--output json` 都會輸出相同的 JSON 結構。

常見欄位：

| 欄位 | 意義 |
| --- | --- |
| `transaction_id` | request/response 配對用識別值 |
| `protocol_id` | 標準 Modbus TCP 應為 0 |
| `length` | MBAP 宣告的後續長度 |
| `unit_id` | Unit/Slave ID |
| `function_code` | 功能碼；response 的最高位可能代表 exception |
| `exception_code` | Modbus exception code，若不是 exception 則為 `null` |
| `warnings` | 截斷、長度不符、非零 protocol ID 等解析警告 |

解析器是 best-effort：即使資料截斷，也會盡量輸出已知欄位並將問題放進 `warnings`。

## 8. 唯讀操作：`read`

**用途與副作用：**依 `TYPE` 建立 FC01–04 唯讀 request，向一個明確 target 開啟 TCP
連線、傳送一次並等待一次 response。即使 Modbus 功能本身是唯讀，仍只能在授權實驗室使用。

語法：

```bash
modbus-cli read TYPE \
  --target HOST \
  [--port PORT] \
  [--timeout SEC] \
  [--unit-id ID] \
  --address ADDRESS \
  --quantity QUANTITY
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `TYPE` | 是 | 無 | `coils`、`discrete-inputs`、`holding-registers` 或 `input-registers` |
| `--target HOST` | 是 | 無 | 單一允許的 IPv4 或可解析 hostname |
| `--port PORT` | 否 | `502` | Modbus TCP port，範圍 1–65535 |
| `--timeout SEC` | 否 | `1.5` | TCP connect/read timeout，必須大於 0 |
| `--unit-id ID` | 否 | `1` | Unit ID |
| `--address ADDRESS` | 是 | 無 | 零起算 protocol address |
| `--quantity QUANTITY` | 是 | 無 | 要讀取的 coil/register 數量，限制依 TYPE 而異 |

`TYPE` 對應如下：

| TYPE | 功能碼 |
| --- | --- |
| `coils` | FC01 |
| `discrete-inputs` | FC02 |
| `holding-registers` | FC03 |
| `input-registers` | FC04 |

### 詳細範例

從私有實驗室目標的 Unit ID 1、address 0 讀取兩個 holding registers：

```bash
modbus-cli read holding-registers \
  --target 192.168.56.10 \
  --port 502 \
  --timeout 1.5 \
  --unit-id 1 \
  --address 0 \
  --quantity 2
```

### 輸出與副作用

命令會在 stdout 輸出 JSON，包括 transport `status`、`elapsed_ms`、`error` 與收到封包時的
`decoded`。每次呼叫建立一條新的 TCP 連線並立即送出一個封包，不會另寫 report 檔案。

輸出中的 `status` 可能是：

| status | 意義 |
| --- | --- |
| `response` | 收到完整 MBAP framing 的 response |
| `timeout` | connect 或讀取逾時 |
| `connection-refused` | 目標拒絕 TCP 連線 |
| `disconnect` | 對方在完整 response 前中斷 |
| `transport-error` | 其他 socket 錯誤 |

即使 `status` 不是 `response`，命令仍可能輸出 JSON 並以 exit code 0 結束；自動化程式不能
只看 shell exit code，還必須檢查 JSON 的 `status`、`error` 和 `decoded`。

目前解析器不會把 FC01–04 response 的資料自動轉成 coil/register 陣列；原始 payload 會在
`decoded.fields.data_hex`。第一個 byte 通常是 byte count，後面才是設備回傳的資料。若要
解讀 16-bit register，還需依設備手冊確認 byte order、word order、signed/unsigned 與資料
型別。

## 9. 最小服務確認：`probe`

**用途與副作用：**固定建立 FC03、address 0、quantity 1 的唯讀 request，以最小的一次
TCP exchange 判斷指定服務是否可能是 Modbus TCP。

語法：

```bash
modbus-cli probe \
  --target HOST \
  [--port PORT] \
  [--timeout SEC] \
  [--unit-id ID]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `--target HOST` | 是 | 無 | 單一允許的 IPv4 或可解析 hostname |
| `--port PORT` | 否 | `502` | Modbus TCP port，範圍 1–65535 |
| `--timeout SEC` | 否 | `1.5` | TCP connect/read timeout，必須大於 0 |
| `--unit-id ID` | 否 | `1` | request 使用的 Unit ID |

### 詳細範例

```bash
modbus-cli probe \
  --target 192.168.56.10 \
  --port 502 \
  --timeout 1.5 \
  --unit-id 1
```

### 輸出與副作用

`probe` 固定建立 FC03、address 0、quantity 1 的 request。它適合做第一次連線確認，但如果
目標的 holding register 0 不存在，Modbus exception 仍可能是正常且有意義的回應。

結果中的 `modbus: likely` 只表示 response 可被目前解析器合理解析，不代表設備型號、韌體或
漏洞已獲確認。命令會立即建立一次 TCP 連線並傳送封包；stdout 為包含 `tcp`、`modbus` 和
`elapsed_ms` 的 JSON，不會另寫檔案。

## 10. 傳送任意 ADU：`send`

**用途與副作用：**把使用者提供的 raw ADU 原樣送到指定 target。此指令不會先限制功能碼，
因此自訂資料可能包含寫入或非標準操作；呼叫後會立即連線。

語法：

```bash
modbus-cli send \
  --target HOST \
  [--port PORT] \
  [--timeout SEC] \
  (--hex HEX | --file FILE) \
  [--no-response] \
  [--output text|json]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `--target HOST` | 是 | 無 | 單一允許的 IPv4 或可解析 hostname |
| `--port PORT` | 否 | `502` | 目的 TCP port，範圍 1–65535 |
| `--timeout SEC` | 否 | `1.5` | TCP connect/read timeout，必須大於 0 |
| `--hex HEX` | 與 `--file` 二選一 | 無 | 要傳送的十六進位 ADU |
| `--file FILE` | 與 `--hex` 二選一 | 無 | 要傳送的 raw binary 檔案 |
| `--no-response` | 否 | 關閉 | 傳送完成後不等待 response；仍會開啟連線並送出封包 |
| `--output FORMAT` | 否 | `text` | `text` 或 `json`；目前兩者都輸出相同 JSON |

### 詳細範例

先解析、再傳送：

```bash
modbus-cli decode --hex 00010000000601030000000A
modbus-cli send \
  --target 192.168.56.10 \
  --port 502 \
  --timeout 1.5 \
  --hex 00010000000601030000000A
```

也可以傳送 raw binary：

```bash
modbus-cli send --target 192.168.56.10 --file request.bin
```

`send` 不會判斷 ADU 是讀取、寫入或非標準功能碼，因此它比 `read` 更需要人工檢查。
呼叫後會立即連線。

```bash
modbus-cli send \
  --target 192.168.56.10 \
  --hex 00010000000601030000000A \
  --no-response
```

### 輸出與副作用

`--no-response` 仍會送出資料，只是不讀取 response；成功傳送時 `status` 為 `sent`。
一般模式會在 stdout 輸出 JSON，其中包含 `status`、`error`、`elapsed_ms`、`request_hex`、
`response_hex` 和 `decoded`；沒有 response 時後兩者為 `null`。每次執行只建立一條新的
TCP 連線，不會另寫檔案。

## 11. 寫入預覽：`write`

**用途與副作用：**以較易讀的高階參數建立 FC05、FC06、FC15 或 FC16 request。目前版本
fail-closed，唯一可成功完成的模式是 `--dry-run`，所以不會真的連線或改變 PLC 狀態。

語法：

```bash
modbus-cli write TYPE \
  --target HOST \
  [--port PORT] \
  [--timeout SEC] \
  [--unit-id ID] \
  --address ADDRESS \
  --values CSV \
  [--dry-run] \
  [--confirm]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `TYPE` | 是 | 無 | `single-coil`、`single-register`、`multiple-coils` 或 `multiple-registers` |
| `--target HOST` | 是 | 無 | parser 仍要求 target；`--dry-run` 不會連線 |
| `--port PORT` | 否 | `502` | 目的 TCP port；目前 `--dry-run` 不使用此值 |
| `--timeout SEC` | 否 | `1.5` | timeout；目前 `--dry-run` 不使用此值 |
| `--unit-id ID` | 否 | `1` | Unit ID |
| `--address ADDRESS` | 是 | 無 | 零起算 protocol address |
| `--values CSV` | 是 | 無 | 逗號分隔整數；接受十進位或 `0x` 前綴 |
| `--dry-run` | 否 | 關閉 | 只建立並顯示 request preview |
| `--confirm` | 否 | 關閉 | 表示使用者確認寫入意圖；目前仍會被預設 policy 拒絕 |

支援的類型：

- `single-coil`
- `single-register`
- `multiple-coils`
- `multiple-registers`

### 詳細範例

只預覽向 address 10 寫入三個 registers 的 request：

```bash
modbus-cli write multiple-registers \
  --target 192.168.56.10 \
  --unit-id 1 \
  --address 10 \
  --values 100,200,300 \
  --dry-run
```

### 輸出與副作用

`--dry-run` 在 stdout 輸出 JSON，包含 `dry_run`、功能碼、address、values 和
`request_hex`，且不解析 target、不建立 TCP 連線。如果同時指定 `--dry-run` 與
`--confirm`，目前會先採用 dry-run 路徑。

目前的預設 `SafetyPolicy` 將實際寫入固定為關閉：

- 沒有 `--dry-run` 或 `--confirm`：拒絕執行。
- 使用 `--dry-run`：只輸出 request preview，不連線。
- 使用 `--confirm`：仍會因預設 policy 禁止寫入而拒絕。

`config init` 產生的 `allow_write_functions` 目前不會改變這個行為。若只是需要建立寫入 ADU
做離線分析，請使用 `build` 或 `write --dry-run`。

## 12. Fuzz corpus：`fuzz`

**用途與副作用：**以固定 seed 產生 deterministic fuzz cases。預設只在本機產生 JSON
corpus；只有明確加入 `--execute` 才會逐案建立 TCP 連線並傳送。

語法：

```bash
modbus-cli fuzz \
  (--target HOST | --scan-report SCAN.json) \
  [--port PORT] \
  [--timeout SEC] \
  [--unit-id ID] \
  [--strategy STRATEGY]... \
  [--requests N] \
  [--rate RATE | --interval SEC] \
  [--concurrency N] \
  [--seed N] \
  [--output FILE] \
  [--execute]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `--target HOST` | 與 `--scan-report` 二選一 | 無 | 直接指定 target；即使離線產生也會解析並套用私網 allowlist |
| `--scan-report FILE` | 與 `--target` 二選一 | 無 | 從 JSON 報告選取 confirmed、fuzz-eligible Modbus/TCP 埠 |
| `--port PORT` | 否 | 直接 target 為 `502` | 直接指定目的埠；或在報告有多個合格候選時消歧義 |
| `--timeout SEC` | 否 | `1.5` | 每個 execute case 的 TCP connect/read timeout |
| `--unit-id ID` | 否 | `1` | 產生 baseline request 時使用的 Unit ID |
| `--strategy STRATEGY` | 否，可重複 | 實際使用 `boundary` | 九種策略之一；多次指定時依順序循環 |
| `--requests N` | 否 | `100` | 案例數，限制 1–10000 |
| `--rate RATE` | 否 | `10` | 每秒最多幾個 request，必須大於 0 且不超過 50 |
| `--interval SEC` | 否 | 無 | 相鄰 request 的等待秒數，必須大於 0；不能與 `--rate` 同時指定 |
| `--concurrency N` | 否 | `1` | 安全限制為 1–4；目前 executor 仍循序執行 |
| `--seed N` | 否 | `1` | deterministic PRNG seed |
| `--output FILE` | 否 | `artifacts/fuzz-report.json` | 完整 case array 的 JSON report；父目錄會自動建立 |
| `--execute` | 否 | 關閉 | 明確允許傳送；省略時只產生 corpus |

### 12.1 詳細範例：先離線產生

```bash
modbus-cli fuzz \
  --target 192.168.56.10 \
  --port 502 \
  --unit-id 1 \
  --strategy boundary \
  --strategy length \
  --requests 20 \
  --seed 12345 \
  --rate 5 \
  --output artifacts/fuzz-report.json
```

沒有 `--execute` 時：

- 不會開啟 TCP 連線。
- 仍會解析 `--target`，並拒絕不在 allowlist 的位址。
- 每個 case 初始 `status` 為 `pending`。
- report 會保存 target、request hex、seed、strategy 和 mutation。
- stderr 不會出現 `TX`/`RX` 逐案紀錄，因為沒有封包被傳送或接收。
- stdout 仍會輸出可機器解析的 JSON 摘要，其中 `executed` 是 `false`。

若指定多個 `--strategy`，案例會依指定順序循環產生。

也可以讓掃描報告提供 target 與 port：

```bash
modbus-cli fuzz \
  --scan-report artifacts/scan-report.json \
  --requests 20 \
  --output artifacts/fuzz-report.json
```

報告被視為不可信輸入：工具會重新驗證 `resolved_address`、要求
`port_summary.scan_complete=true` 與已知的終態分類，並交叉檢查綁定同一 TCP 埠的
`protocol_valid` Modbus observation；只有
`open + modbus-tcp + confirmed + fuzz_eligible` 才能成為候選。`INCONCLUSIVE` 只表示未辨認
出 OpenPLC 世代，不會阻擋已嚴格確認的 Modbus 埠。沒有候選或有多個候選但未指定
`--port` 時會拒絕，不會退回猜測 502。

搭配 `--scan-report --execute` 時，在第一個 fuzz case 前還會用相同 `--unit-id` 發出一次
唯讀 FC03 protocol-correlation preflight，重新確認目前 endpoint 的 Modbus
request/response correlation；合法 exception 也可通過，因此它不代表應用程式健康。
preflight 失敗時不會傳送 fuzz cases；因此這種執行方式會比 `--requests` 多一個唯讀網路
request。成功後會等待一個 fuzz interval 才送第一個 case，避免略過設定的 pacing。

### 12.2 支援策略

| strategy | 修改內容 |
| --- | --- |
| `boundary` | quantity 的邊界與越界值 |
| `bitflip` | 隨機一個 bit |
| `byteflip` | 隨機一個 byte |
| `length` | MBAP length |
| `function-code` | 功能碼 |
| `transaction` | transaction ID |
| `unit-id` | Unit ID |
| `semantic` | 位址/數量的語意不一致 |
| `random` | 1–4 個 byte 的隨機替換 |

未指定策略時使用 `boundary`。

### 12.3 節奏與硬限制

| 參數 | 意義 | 限制 |
| --- | --- | --- |
| `--requests N` | Fuzz 案例數 | 1–10000；report execute 另有 1 個 preflight |
| `--rate R` | 每秒最多幾個 request | 大於 0、最多 50；預設 10 |
| `--interval SEC` | 相鄰 request 的等待秒數 | 大於 0 |
| `--concurrency N` | 安全限制欄位 | 1–4；目前 executor 仍是循序傳送 |
| `--seed N` | deterministic PRNG seed | 預設 1 |

`--rate` 和 `--interval` 不能同時指定。`--interval 0.5` 相當於每秒最多 2 個 fuzz
requests；report-driven preflight 與第一個 case 之間也會等待 0.5 秒。

### 12.4 顯式執行

人工檢查 corpus、快照和 health request 後：

```bash
modbus-cli fuzz \
  --scan-report artifacts/scan-report.json \
  --unit-id 1 \
  --requests 10 \
  --strategy boundary \
  --interval 1 \
  --seed 12345 \
  --output artifacts/executed-report.json \
  --execute
```

這個命令會先執行 report handoff 驗證與一個唯讀 FC03 preflight。`--execute` 會按照參數
重新產生案例，不會讀取先前的 fuzz corpus；若要執行已人工審查的 deterministic cases，
scan report、Unit ID、策略順序、案例數與 seed 必須保持一致。

使用 `--execute` 時，每個案例會把即時進度寫到 **stderr**。`TX` 顯示突變後實際送出的
功能類型、目的地與策略；`RX` 顯示實際 response 類型、transport 狀態、延遲與保守分類。
例如：

```text
[case-000001] TX request-type=read-holding-registers (FC 0x03); target=192.168.56.10:502; strategy=boundary
[case-000001] RX response-type=exception-response/read-holding-registers (FC 0x83, exception=illegal-data-address 0x02); status=response; elapsed_ms=1.250; classification=normal-or-exception-response
```

`request-type` 依突變後封包的實際 function code 判定；例如 `function-code`、`bitflip` 或
`random` 可能使它成為 `unknown (FC 0xNN)`；若連 function code 都不可用，則顯示
`malformed-request (function code unavailable)`。功能碼最高 bit 被設為 1 時會附上
`exception-bit-set`，framing 有警告時會附上 `malformed framing`。不能假定所有案例都是
baseline FC03。

突變後的實際 payload 在建立 socket 前還會再套用唯讀功能碼 allowlist，並要求恰好一個
完整 MBAP ADU（protocol ID 0、宣告長度與實際長度一致、不得尾隨或串接第二個 ADU）。
FC43 只允許完整的 MEI 0x0E Read Device Identification；可讀寫的其他 MEI subtype 會封鎖。
FC05、FC06、FC15、FC16、未知功能碼或無法安全判定 framing 的 request 會保留在 report，但標為
`status=blocked`、`classification=blocked-by-safety-policy`，不會傳送。stderr 會顯示
`BLOCKED`，stdout 摘要中的 `executed_cases` 與 `blocked_cases` 可用來核對實際結果。

因此 `length` strategy 適合離線 corpus/decoder 測試；其刻意不一致的 MBAP length 在
`--execute` 時會被 transport boundary 封鎖。`bitflip`、`byteflip` 或 `random` 若改到
MBAP framing，也會同樣保留案例但不送出。

如果 transport 沒有回傳任何 bytes，CLI 不會虛構 Modbus response 類型，而會顯示
`response-type=no-packet`，並保留真正的 transport 狀態與分類：

```text
[case-000002] RX response-type=no-packet; status=timeout; elapsed_ms=1500.000; classification=possible-service-degradation
```

`no-packet` 也可能搭配 `connection-refused`、`disconnect` 或 `transport-error`；它只表示
該次沒有 response bytes，不等於已證實服務 crash。response type 的判讀如下：

| `response-type` | 意義 |
| --- | --- |
| `normal-response/FUNCTION` | 收到無 parser warning 的一般 Modbus response |
| `exception-response/FUNCTION` | 功能碼最高 bit 為 1；同時顯示 exception 名稱與代碼 |
| `malformed-response/FUNCTION` | 收到 bytes 和功能碼，但 framing 有 parser warning |
| `malformed-response (function code unavailable)` | 收到 bytes，但不足以取得功能碼 |
| `no-packet` | transport 沒有回傳任何 bytes |

若 exception response 同時有 framing warning，仍保留 `exception-response/FUNCTION`，並在
括號內附上 `malformed framing`。

逐案 stderr 不會破壞 stdout 的 JSON。需要分開保存時可使用：

```bash
mkdir -p artifacts
modbus-cli fuzz \
  --target 192.168.56.10 \
  --requests 10 \
  --interval 1 \
  --output artifacts/executed-report.json \
  --execute \
  > artifacts/fuzz-summary.json \
  2> artifacts/fuzz-progress.log
```

stdout 摘要維持以下欄位：

```json
{
  "seed": 1,
  "cases": 10,
  "executed": true,
  "executed_cases": 10,
  "blocked_cases": 0,
  "interval": 1.0,
  "target": {
    "host": "192.168.56.10",
    "port": 502,
    "source": "direct"
  },
  "preflight_verified": false,
  "report": "artifacts/executed-report.json"
}
```

目前 executor 逐案建立 TCP 連線並循序傳送。timeout 只會分類為
`possible-service-degradation`，不能單憑一次 timeout 宣稱服務 crash 或存在 CVE。

常見 `classification`：

| classification | 意義 |
| --- | --- |
| `normal-or-exception-response` | 一般 response 或可解析的 Modbus exception |
| `possible-service-degradation` | 本次案例 timeout，需要 health check 和重播確認 |
| `anomalous-transport` | connection error、disconnect 等傳輸異常 |
| `possible-parser-inconsistency` | 收到的 response 有結構警告 |
| `blocked-by-safety-policy` | 突變後不是明確唯讀 request，未建立 socket |
| `inconclusive` | 尚未執行或證據不足 |

### 12.5 輸出與副作用

- 不加 `--execute`：只覆寫或建立 `--output` 指定的 JSON report，stdout 是摘要 JSON，
  stderr 沒有逐案 `TX`/`RX`。
- 加 `--execute`：每個 case 建立一條新的 TCP 連線，stderr 即時顯示 `TX`/`RX`，完成後
  report 保存 request、response、時間、status 與 classification，stdout 仍只輸出摘要 JSON。
- JSON report 和 stdout/stderr 可以分別重新導向；`--output` report 不會因重新導向 stdout
  而消失。

## 13. 重播：`replay`

**用途與副作用：**從 fuzz case JSON 讀取已保存的 target 與 `request_hex`；通過相同的 fuzz
唯讀功能碼檢查後立即重送。輸入若是 array，只使用第一筆 case。寫入、未知或無功能碼案例
會在建立 socket 前被拒絕。

語法：

```bash
modbus-cli replay CASE \
  [--times N] \
  [--timeout SEC] \
  [--interval SEC]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `CASE` | 是 | 無 | 單一 case object 或 case array 的 JSON 檔案路徑 |
| `--times N` | 否 | `1` | 重播次數，範圍 1–10000 |
| `--timeout SEC` | 否 | `1.5` | 每次 TCP exchange 的 timeout |
| `--interval SEC` | 否 | `0.02` | 相鄰重播間隔，必須大於 0；最快 50 次/秒 |

### 詳細範例

將 report 第一筆案例重播三次，每次之間等待一秒：

```bash
modbus-cli replay artifacts/fuzz-report.json \
  --times 3 \
  --timeout 1.5 \
  --interval 1
```

### 輸出與副作用

重要行為：

- `replay` 會在唯讀安全檢查通過後立即連到 JSON 內 `target.host` 和 `target.port`，沒有第二個
  確認參數。
- 輸入可以是單一 case object 或 case array；array 只會重播第一個 case。
- `replay` 與 fuzz 共用 1–10000 次、最高 50 次/秒的硬限制；`--interval 0` 會被拒絕。
- 安全檢查要求單一完整 MBAP ADU，會封鎖尾隨/串接 ADU 與非 MEI 0x0E 的 FC43。
- `stable: true` 只表示每次 transport `status` 相同，不表示問題已證實或 response 完全相同。

stdout 是包含 `case_id`、`results` 和 `stable` 的 JSON。命令最多建立 `--times` 條新 TCP
連線，不修改輸入 report，也不另寫輸出檔。如果 report 是別人提供的，務必先打開檔案確認
target 和 request，再執行 replay。

## 14. 結構最小化：`minimize`

**用途與副作用：**離線裁切 fuzz case，作為人工調查的結構 baseline。它不執行
delta-debugging，也不會自動連線驗證結果。

語法：

```bash
modbus-cli minimize CASE
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `CASE` | 是 | 無 | 單一 case object 或 case array 的 JSON 檔案；array 只使用第一筆 |

### 詳細範例

```bash
modbus-cli minimize artifacts/fuzz-report.json
```

### 輸出與副作用

它會：

1. 讀取單一 case，或 array 的第一個 case。
2. 將 `request_hex` 裁切到前 24 個 hex 字元（12 bytes）。
3. 只保留第一筆 mutation。
4. 在原檔旁寫入 `<原檔名>-minimized.json`。

它不會連線，也不會驗證裁切後案例能否重現結果。這只是結構 baseline，不是完整的
delta-debugging。若同名的 minimized 檔已存在，目前會直接覆寫；stdout 會輸出新檔路徑與
需要 replay 驗證的提示。

## 15. 設定檔：`config`

**用途與副作用：**建立、顯示或做最低限度驗證的 TOML 設定檔。這些 action 都不連線；
`init` 會寫檔，`show` 和 `validate` 只讀檔。

語法：

```bash
modbus-cli config ACTION [--file FILE]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `ACTION` | 是 | 無 | `init`、`show` 或 `validate` |
| `--file FILE` | 否 | `~/.config/modbus-cli/config.toml` | 要建立或讀取的 TOML 路徑 |

### 詳細範例

依序建立、驗證並顯示同一份 lab 設定：

```bash
modbus-cli config init --file lab.toml
modbus-cli config validate --file lab.toml
modbus-cli config show --file lab.toml
```

### 輸出與副作用

`init` 的 stdout JSON 會回報 `created` 路徑；`validate` 回報 `valid` 與檔案路徑；`show`
把 TOML 資料轉成 JSON 顯示。若 `lab.toml` 已存在，`init` 會直接覆寫，執行前請先確認
檔名。`validate` 目前只檢查 TOML 能否解析，以及存在的 `[safety]` 是否為 table；它不是
完整設定 schema 驗證。

若省略 `--file`，預設位置是：

```text
~/.config/modbus-cli/config.toml
```

目前 `config` 只負責建立、顯示和驗證檔案。其他指令尚未讀取設定檔，因此 target、port、
rate、寫入權限等仍須以 CLI 實際行為為準。

## 16. 插件

**用途與副作用：**從 Python entry point group `modbus_cli.plugins` 列出插件，或載入指定
插件並檢查必要 metadata。核心指令本身不建立網路連線或修改插件。

語法：

```bash
modbus-cli plugins ACTION [NAME]
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| `ACTION` | 是 | 無 | `list`、`info` 或 `validate` |
| `NAME` | `info`、`validate` 必填；`list` 不需要 | 無 | 已安裝插件的 entry point 名稱 |

### 詳細範例

先列出插件，再查看並驗證名為 `example` 的插件：

```bash
modbus-cli plugins list
modbus-cli plugins info example
modbus-cli plugins validate example
```

### 輸出與副作用

插件透過 Python entry point group `modbus_cli.plugins` 發現。沒有安裝任何插件時，
`plugins list` 會輸出空陣列。開發方式請見
[`plugin-development.md`](plugin-development.md)。

`list` 的 stdout 是插件 `name`/`value` array；目前 `info` 與 `validate` 都會執行相同的
metadata validation，輸出插件名稱及 validation 結果。指定不存在的插件會以 exit code 2
失敗。這些 action 不寫檔，但 `info`/`validate` 會載入第三方插件 Python object。

## 17. 版本與環境資訊

### 17.1 `version` 與全域 `--version`

**用途與副作用：**在本機顯示套件版本，不連線、不讀寫設定檔。

語法與完整參數：

| 語法 | 額外參數 | 預設 | 輸出 |
| --- | --- | --- | --- |
| `modbus-cli --version` | 無 | 無 | 純文字版本字串 |
| `modbus-cli version` | 無 | 無 | `{"version": "..."}` JSON |

#### 詳細範例

```bash
modbus-cli --version
modbus-cli version
```

#### 輸出與副作用

兩種形式都只讀取內建版本資訊並以 exit code 0 結束。`mbfuzz --version` 與
`mbfuzz version` 的結果相同。

### 17.2 `info`

**用途與副作用：**顯示目前執行環境和已發現插件，不連線、不寫檔。

語法：

```bash
modbus-cli info
```

完整參數：

| 參數 | 必填 | 預設 | 意義 |
| --- | --- | --- | --- |
| 無 | — | — | `info` 不接受 command-specific 參數 |

#### 詳細範例

```bash
modbus-cli info
```

#### 輸出與副作用

stdout JSON 會列出 CLI 版本、Python 版本、transport、fuzz strategies、已發現插件和預設
設定檔位置。插件 discovery 只讀取 Python entry point metadata；命令不開啟網路連線。

## 18. Exit code 與自動化

| exit code | 意義 |
| --- | --- |
| `0` | command 完成；網路操作仍須檢查輸出的 `status` |
| `2` | 參數、檔案、解析、安全策略或執行錯誤 |
| `3` | `scan` 完成但分類衝突，或硬性 network-action budget 使掃描不完整 |

範例：

```bash
if ! output="$(modbus-cli read holding-registers \
  --target 192.168.56.10 --address 0 --quantity 1)"; then
  echo "CLI 執行失敗" >&2
  exit 1
fi

printf '%s\n' "$output"
```

正式自動化時還應用 JSON 工具檢查 `status == "response"`，不能只依賴 exit code。

## 19. 常見問題

### `target ... is outside allowed laboratory networks`

解析後 IP 不在預設 allowlist。請確認沒有打錯 IP、DNS 沒有指到公網，而且測試目標確實位於
隔離私網。不要為了繞過錯誤而把生產設備搬進允許範圍。

### `cannot resolve target`

hostname 無法解析，或不是可用的 IPv4。改用已經由實驗室主控台核對過的 IPv4。

### `connection-refused`

目標可達，但指定 port 沒有 listener。確認 Modbus TCP 服務已啟動、Docker port mapping
正確，並檢查 `--port`。

### `timeout`

可能是防火牆、路由、錯誤 Unit ID、服務沒有回應或測試案例造成的暫時異常。單次 timeout
不是漏洞證據；停止測試並執行已知正常的 health request、檢查服務日誌，再決定是否重播。

### `illegal-data-address`

服務有回應，但位址不支援。核對零起算/一基位址差異、資料類型和允許範圍。

### `MBAP length mismatch`

封包 header 宣告的 length 與實際 byte 數不同。若這是 fuzz case，屬於預期的 mutation；
若是一般 request，請重新用 `build` 產生。

### `writes require --confirm` 或 `writes are disabled`

目前版本只允許 `write --dry-run` 預覽。`--confirm` 不會繞過預設禁止寫入的 policy。

## 20. 建議的完整測試流程

1. 建立隔離環境、快照目標並記錄 IP/port/Unit ID。
2. 用 `build` 和 `decode` 離線確認 request。
3. 用 `read` 傳送一筆已知安全的唯讀 request。
4. 保存正常 response、PLC 日誌和封包擷取，作為 health baseline。
5. 用沒有 `--execute` 的 `fuzz` 產生 corpus。
6. 人工檢查 target、案例數、rate、seed 和 request。
7. 在低速率下加 `--execute`，同時觀察服務和實體狀態。
8. 測試後再次執行 health request，比對狀態和日誌。
9. 只有在同一案例可重播、health check 有一致異常且有其他證據時，才進一步調查。
10. 復原測試資料或還原快照，保存不含憑證的報告。

隔離與收尾細節請見 [`openplc-lab.md`](openplc-lab.md)。
