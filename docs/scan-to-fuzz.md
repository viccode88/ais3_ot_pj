# PLC 端口掃描與 Scan → Fuzz 完整指南

本指南集中說明本專案整合後的兩個功能：

1. 對單一已授權 IP 掃描多個 TCP 埠，標記 PLC/ICS 關聯度並辨識可確認的協定。
2. 將完整的 JSON 掃描報告安全交給 Modbus fuzz，先離線產生案例，再選擇是否執行。

`modbus-cli` 是建議的整合入口；`plcfp scan` 保留為進階相容入口。所有主動操作都只應在
你擁有或明確獲准測試的隔離實驗室中使用。

## 1. 最短可用流程

### 步驟 1：先看人類可讀的掃描結果

```bash
modbus-cli scan \
  --target 192.168.56.10 \
  --profile safe \
  --max-layer 2 \
  --format text
```

這個命令會連線。表格中的 `HIGH` 表示 PLC/工控關聯度高，不等於協定已確認；判斷服務時
還要看 `IDENTIFICATION`：

```text
PLC   PORT/TCP  STATE  IDENTIFICATION  FUZZ  SERVICE
----  --------  -----  --------------  ----  ------------------------------
HIGH  502       open   confirmed       yes   Modbus/TCP
CTX   8080      open   configured      no    OpenPLC v3 web interface
LOW   22        open   port-hint       no    SSH remote management
```

### 步驟 2：保存可交給 fuzz 的 JSON

`fuzz --scan-report` 只接受 JSON，不可把 text、CSV 或 SARIF 當成交接檔：

```bash
mkdir -p artifacts

modbus-cli scan \
  --target 192.168.56.10 \
  --profile safe \
  --max-layer 2 \
  --format json \
  --no-raw \
  --output artifacts/scan-report.json
```

輸出格式由 `--format` 決定，不是副檔名：若使用
`--format text --output artifacts/scan-report.json`，檔案內容仍然是 text，無法交接。
`--no-raw` 只移除 base64 原始回應，不會移除交接所需的結構化協定驗證 metadata。

在進入 fuzz 前檢查完整性與候選埠：

```bash
python - <<'PY'
import json

with open("artifacts/scan-report.json", encoding="utf-8") as stream:
    report = json.load(stream)

summary = report.get("port_summary", {})
print("status:", report.get("status"))
print("scan_complete:", summary.get("scan_complete"))
print("fuzz_candidates:", summary.get("fuzz_candidates"))

if report.get("status") == "BUDGET_EXCEEDED":
    raise SystemExit("STOP: network-action budget exceeded")
if summary.get("scan_complete") is not True:
    raise SystemExit("STOP: scan is incomplete")
if not summary.get("fuzz_candidates"):
    raise SystemExit("STOP: no confirmed Modbus/TCP fuzz candidate")
PY
```

### 步驟 3：離線產生 deterministic fuzz corpus

```bash
modbus-cli fuzz \
  --scan-report artifacts/scan-report.json \
  --unit-id 1 \
  --strategy boundary \
  --strategy semantic \
  --requests 10 \
  --interval 1 \
  --seed 20260726 \
  --output artifacts/fuzz-review.json
```

沒有 `--execute`，所以這一步不會建立 fuzz TCP 連線。請檢查：

```bash
python -m json.tool artifacts/fuzz-review.json
```

也可以只列出人工審查最重要的欄位：

```bash
python - <<'PY'
import json

with open("artifacts/fuzz-review.json", encoding="utf-8") as stream:
    cases = json.load(stream)

for case in cases:
    print(
        case["case_id"],
        "target=", case["target"],
        "strategy=", case["strategy"],
        "mutations=", case["mutations"],
        "request_hex=", case["request_hex"],
        "status=", case["status"],
    )
PY
```

### 步驟 4：在隔離環境執行同一組案例

`--execute` 不會讀取 `artifacts/fuzz-review.json`；它會重新產生案例。案例由 scan report、
seed、策略順序、案例數與 Unit ID 決定，因此下列參數必須與離線審查時一致：

```bash
modbus-cli fuzz \
  --scan-report artifacts/scan-report.json \
  --unit-id 1 \
  --strategy boundary \
  --strategy semantic \
  --requests 10 \
  --interval 1 \
  --seed 20260726 \
  --output artifacts/fuzz-executed.json \
  --execute
```

報告驅動的 `--execute` 會先多送一個相同 Unit ID 的唯讀 FC03 protocol-correlation
preflight，成功後等待一個 fuzz interval。只有
transaction ID、protocol ID、Unit ID、MBAP 長度及 FC03 response 結構都正確，才會開始送
fuzz cases。正常 FC03 response 或合法的 FC03 exception response 都可通過；原樣 echo
不會。因為 exception 也可通過，preflight 只確認目前仍是相關聯的 Modbus endpoint，不代表
應用程式健康或 address 0 可讀。

## 2. 哪些步驟會送封包

| 操作 | 是否連線 | 說明 |
| --- | --- | --- |
| `scan` | 是 | TCP connect，並依角色埠執行安全協定 probe |
| `fuzz`，不加 `--execute` | 否 | 只產生 JSON corpus；仍會解析並驗證 target |
| `fuzz --scan-report ... --execute` | 是 | 先送 1 個 FC03 preflight，再逐案傳送 |
| `replay` | 是 | 立即重送 report 第一筆安全檢查通過的案例 |
| `send` | 是 | Expert raw transport；可送任意 ADU，包含寫入功能碼 |
| `build`、`decode`、`minimize` | 否 | 純離線操作 |

預設只允許 loopback 與 RFC1918 私有 IPv4。這個 allowlist 不是授權機制；即使 IP 被接受，
操作員仍須確認測試授權、PLC process safety、復原方法與觀測方式。

本指南後述的唯讀 allowlist、single-ADU 與 FC43 MEI 安全閘只適用 `fuzz`/`replay`，不適用
raw `send`。使用 `send` 前必須先以 `decode` 人工確認功能碼與完整 payload。

## 3. 掃描語法與參數

```bash
modbus-cli scan \
  --target HOST \
  [--profile safe|standard|lab] \
  [--max-layer 1|2|3|4] \
  [--timeout SEC] \
  [--scan-interval SEC] \
  [--packet-budget COUNT] \
  [--ports SPEC] \
  [--modbus-port PORT] \
  [--v3-http-port PORT] \
  [--v4-https-port PORT] \
  [--enip-port PORT] \
  [--dnp3-port PORT] \
  [--opcua-port PORT] \
  [--dnp3-address ADDRESS] \
  [--signature-dir DIR] \
  [--format json|text|csv|sarif] \
  [--output PATH] \
  [--no-raw]
```

### Profile 預設值

| Profile | 探測間隔 | Network-action budget | Timeout | 適合情境 |
| --- | ---: | ---: | ---: | --- |
| `safe` | 0.5 秒 | 60 | 10 秒 | 第一輪資產辨識；`modbus-cli scan` 預設 |
| `standard` | 0.2 秒 | 300 | 10 秒 | 已知穩定的隔離測試設備 |
| `lab` | 0.05 秒 | 1000 | 10 秒 | 專用測試環境；DNP3 主動 probe 必須使用 |

命令列的 `--scan-interval`、`--packet-budget`、`--timeout` 可覆寫 profile 數值。所有協定
probe 共用同一個硬性 scheduler-action budget。`--packet-budget` 是歷史 CLI 名稱，不是
wire-packet cap：每次 TCP connect、HTTP request、Modbus exchange 等高階 action 計數一次，
而一個 action 可能產生多個 TCP/IP packets。JSON 的 `packets_sent` 也表示 action 數。
`--signature-dir` 用於載入外部 OpenPLC 簽章資料庫；一般端口掃描可省略。

### 角色埠

| 參數 | 預設 | 主動確認 |
| --- | ---: | --- |
| `--modbus-port` | 502 | Modbus/TCP |
| `--v3-http-port` | 8080 | OpenPLC v3 HTTP |
| `--v4-https-port` | 8443 | OpenPLC v4 HTTPS / Engine.IO |
| `--enip-port` | 44818 | EtherNet/IP |
| `--dnp3-port` | 20000 | DNP3；另需 lab profile、L3 與 address |
| `--opcua-port` | 4840 | OPC UA TCP Hello/Acknowledge |

### 實際主動流量矩陣

Profile 與 layer 會共同影響流量，不能只看 `--max-layer`：

| 條件 | 對已開放角色埠執行的動作 |
| --- | --- |
| L1，所有 profile | 每個 catalog/自訂埠 TCP connect；v4 HTTPS 角色埠另做 TLS handshake |
| L2，所有 profile | v3 的 6 個基礎 GET 與 12 個 route GET；v4 的 4 個 GET、空 body login POST 與 Engine.IO polling handshake；OPC UA Hello；Modbus FC43 加 Unit ID 0/1/247/255 的 FC03 matrix |
| L2，safe | EtherNet/IP UDP ListIdentity |
| L2，standard/lab | UDP ListIdentity，加 TCP RegisterSession、ListServices、ListInterfaces、NOP |
| L3，standard/lab | 唯讀 Modbus function bitmap、位址邊界查詢與 30 次 timing samples |
| L3，lab + DNP3 address | DNP3 Link Status |
| L4 | 目前沒有比 L3 多的獨立 probe，保留為最高層相容值 |

所有動作只有在對應 TCP 角色埠先被掃描為 open 時才會啟動。v3 route matrix 包含
`/reload-program`、`/upload-program`、`/restore_custom_hardware` 與 Modbus device 管理等
action-named 路徑，但只會使用無 body、未認證 GET；目標仍可能留下 access/audit log。
空 login POST 不含帳密，但可能
留下失敗登入/audit log；Engine.IO handshake 可能建立短暫 session；EtherNet/IP discovery
可能同時使用 UDP 與 TCP。掃描器不呼叫 `/api/create-user`，也不送設定變更 payload；
但無法保證客製目標的 GET handler 沒有非標準副作用，所以仍必須在隔離環境執行。

### `--ports` 與角色埠的差別

- `--ports 5000-5010` 是「額外 TCP connect 範圍」，會加入預設 catalog，不會取代它。
- `--modbus-port 1502` 是「把 TCP/1502 指定為 Modbus 角色並做上層確認」，而且會自動加入
  掃描，不必再寫 `--ports 1502`。
- 角色埠只移動主動 probe，不會移除標準 catalog 埠；`--modbus-port 1502` 之後，502 仍會
  做 TCP connect 並保留 Modbus port-hint。
- 只寫 `--ports 1502` 不會把未知服務強行當成 Modbus；若要確認非標準 Modbus 埠，必須用
  `--modbus-port 1502`。
- 自訂角色埠與 `--ports` 額外埠會排在預設 catalog 前面，較小的 budget 會先處理它們。
- 每個角色一次只能指定一個埠。若同一 IP 有多個非標準 Modbus endpoint，請分別執行多次
  scan，每次指定不同的 `--modbus-port`。

非標準 OpenPLC/工控服務範例：

```bash
modbus-cli scan \
  --target 127.0.0.1 \
  --modbus-port 1502 \
  --v3-http-port 18080 \
  --enip-port 14418 \
  --profile safe \
  --max-layer 2 \
  --format text
```

DNP3 主動探測只允許 lab profile，且必須提供 outstation address：

```bash
modbus-cli scan \
  --target 192.168.56.20 \
  --profile lab \
  --max-layer 3 \
  --dnp3-port 20000 \
  --dnp3-address 1 \
  --format json \
  --output artifacts/dnp3-scan.json
```

## 4. 預設 PLC/ICS TCP catalog

掃描器預設檢查下列候選埠。這張表是服務提示，不是協定證明：

| TCP port | 服務候選 | 預設關聯度 |
| ---: | --- | --- |
| 22 | SSH 管理 | low |
| 80、443 | HTTP / HTTPS 管理介面 | contextual |
| 102 | Siemens S7comm / ISO-on-TCP | high |
| 502 | Modbus/TCP | high |
| 802 | Modbus Security | high |
| 1217 | CODESYS Gateway / Schneider SoMachine | high |
| 1883 | MQTT broker | medium |
| 1962 | Phoenix Contact PC Worx | high |
| 2404 | IEC 60870-5-104 | high |
| 2455 | WAGO I/O System | high |
| 4840、4843 | OPC UA / OPC UA over TLS | high |
| 5094 | HART-IP | high |
| 8080、8443 | Alternate Web / OpenPLC Web 候選 | contextual |
| 9600 | Omron FINS/TCP | high |
| 11740 | CODESYS engineering channel | high |
| 18245 | GE SRTP | high |
| 20000 | DNP3 | high |
| 44818 | EtherNet/IP | high |

任意開放埠都可以列入結果；不在 catalog、也沒有已配置角色或有效協定證據時，會顯示
`service_id=unknown` 與 `plc_relevance=unknown`。

## 5. 如何解讀結果

### `state`

| 值 | 意義 |
| --- | --- |
| `open` | TCP connect 成功，或有綁定該 TCP endpoint 的有效主動協定證據 |
| `closed` | 連線被拒絕或 reset |
| `unavailable` | 已嘗試，但因 timeout、網路或探測錯誤無法判定 |
| `not-scanned` | 硬性 network-action budget 用盡前尚未探測；不能當成 closed |

### `plc_relevance`

| JSON 值 | Text 標記 | 意義 |
| --- | --- | --- |
| `high` | `HIGH` | 與 PLC/ICS 協定高度相關 |
| `medium` | `MED` | 常見於工控整合，但不是 PLC 專屬 |
| `contextual` | `CTX` | Web/管理介面等，需搭配其他證據 |
| `low` | `LOW` | 一般管理服務 |
| `unknown` | `UNK` | catalog 與 probe 都無法辨識 |

關聯度回答「這個服務和 PLC 有多相關」，不回答「協定是否已確認」。

### `identification`

| 值 | 意義 |
| --- | --- |
| `port-hint` | 只根據 catalog 常見埠提示 |
| `configured` | 該埠被配置為協定角色，但 probe 尚未確認 |
| `confirmed` | 上層 response 已通過結構、request correlation 與 transport 綁定 |
| `unknown` | 無足夠服務線索 |

Modbus、OPC UA、DNP3 與 EtherNet/IP 都不會只因為收到任意 bytes 或 request echo 就標成
`confirmed`。UDP EtherNet/IP ListIdentity 證據也不會被誤用來確認一個 TCP finding。

### `fuzz_eligible`

只有同時符合以下條件才是 `true`：

1. `state=open`
2. `service_id=modbus-tcp`
3. `identification=confirmed`
4. 掃描報告內有綁定同一 port、`transport=tcp`、`protocol_valid=true` 的 Modbus observation

開放 502/tcp 本身不夠。

## 6. JSON 欄位

簡化範例：

```json
{
  "target": "192.168.56.10",
  "resolved_address": "192.168.56.10",
  "status": "INCONCLUSIVE",
  "port_summary": {
    "scan_complete": true,
    "requested": 21,
    "scanned": 21,
    "not_scanned": 0,
    "open": 2,
    "closed": 19,
    "unavailable": 0,
    "high_relevance_open": [502],
    "confirmed_services": [
      {"port": 502, "service": "modbus-tcp"}
    ],
    "fuzz_candidates": [502]
  },
  "port_findings": [
    {
      "port": 502,
      "transport": "tcp",
      "state": "open",
      "service_id": "modbus-tcp",
      "service_name": "Modbus/TCP",
      "plc_relevance": "high",
      "identification": "confirmed",
      "evidence": ["active-confirmation: correlated Modbus response"],
      "latency_ms": 1.25,
      "fuzz_eligible": true,
      "alternatives": []
    }
  ]
}
```

實際報告還會包含 `observations`、OpenPLC `evidence`、版本範圍、生命週期、
network-action 數（歷史欄位 `packets_sent`）及簽章資料庫版本。

### `status` 與 `scan_complete` 不同

| 欄位/值 | 意義 |
| --- | --- |
| `port_summary.scan_complete=true` | 掃描流程與 network-action budget 完整 |
| `status=complete` | 掃描完成，且 OpenPLC 世代分類有結果 |
| `status=INCONCLUSIVE` | 掃描可以是完整的，只是無法辨認 OpenPLC 世代 |
| `status=CONFLICT` | 同時存在互相衝突的 OpenPLC 強證據 |
| `status=FORKED` | 行為相似，但資產與已知完整基準不一致 |
| `status=BUDGET_EXCEEDED` | 硬性 budget 中止；`scan_complete=false` |

因此一般 Modbus PLC 很可能是 `status=INCONCLUSIVE`，仍可在 `scan_complete=true` 且 Modbus
證據有效時交給 fuzz。

### 其他輸出格式

- `text`：供操作員快速查看，只列開放埠並顯示關聯標記、確認狀態與證據。
- `csv`：包含 port row、OpenPLC evidence row 或 summary row，適合表格匯入。
- `sarif`：高關聯開放埠會成為 `PLC-RELATED-PORT` result，完整 port findings 保存在 run
  properties。
- `json`：唯一可用於 `fuzz --scan-report` 的格式。

## 7. Scan report 如何交給 fuzz

Fuzz 語法：

```bash
modbus-cli fuzz \
  (--target HOST | --scan-report SCAN.json) \
  [--port PORT] \
  [--timeout SEC] \
  [--unit-id ID] \
  [--strategy STRATEGY]... \
  [--requests COUNT] \
  [--rate RPS | --interval SEC] \
  [--concurrency COUNT] \
  [--seed SEED] \
  [--output PATH] \
  [--execute]
```

| 參數 | 預設 | 意義 |
| --- | --- | --- |
| `--target` / `--scan-report` | 二選一 | 直接 endpoint，或使用已確認的 JSON scan report |
| `--port` | direct 模式為 502 | 直接目的埠，或對 scan report 多候選消歧義 |
| `--timeout` | 1.5 秒 | 每次 TCP connect/read timeout |
| `--unit-id` | 1 | baseline 與 report-driven preflight 使用的 Unit ID |
| `--strategy` | `boundary` | 可重複指定；依順序循環 |
| `--requests` | 100 | Fuzz 案例數，範圍 1–10000；report execute 另有 1 個 preflight |
| `--rate` | 10/s | 最大傳送率，上限 50/s |
| `--interval` | 無 | 取代 rate，指定相鄰案例等待秒數；必須大於 0 |
| `--concurrency` | 1 | 安全限制 1–4；目前仍循序執行 |
| `--seed` | 1 | deterministic PRNG seed |
| `--output` | `artifacts/fuzz-report.json` | 完整案例 JSON |
| `--execute` | 關閉 | 省略時只產生 corpus；指定後才傳送 |

`--rate` 與 `--interval` 互斥。

交接時報告被視為不可信輸入。工具會：

1. 重新解析 JSON，要求 top-level object。
2. 重新用私網 policy 驗證 `resolved_address`。
3. 接受已知分類終態：`complete`、`INCONCLUSIVE`、`CONFLICT`、`FORKED`。
4. 要求 `port_summary.scan_complete=true`，拒絕 `BUDGET_EXCEEDED`。
5. 只選取 open、confirmed、fuzz-eligible 的 `modbus-tcp` finding。
6. 交叉檢查同一 TCP port 的 `protocol_valid` Modbus observation。
7. 若有多個候選，要求操作員用 `--port` 明確選擇。
8. `--execute` 前再發出一個 correlated FC03 preflight。

多候選範例：

```bash
modbus-cli fuzz \
  --scan-report artifacts/scan-report.json \
  --port 1502 \
  --unit-id 247 \
  --requests 10 \
  --interval 1 \
  --output artifacts/fuzz-1502.json
```

也可以不用 scan report，直接指定已知 endpoint：

```bash
modbus-cli fuzz \
  --target 192.168.56.10 \
  --port 502 \
  --unit-id 1 \
  --requests 10 \
  --output artifacts/direct-fuzz.json
```

直接指定模式不會聲稱 endpoint 是掃描確認的服務；只有 `--execute` 才會送 fuzz cases。

## 8. 主動 fuzz 的安全邊界

- `--requests` 限制的是 fuzz cases；report-driven execute 會額外送 1 個 FC03 preflight。
- Rate 必須大於 0 且最多 50 fuzz requests/second；preflight 成功後會等待一個相同 interval
  才送第一個 case，executor 目前仍循序執行。
- 每個 mutation 在 socket 建立前重新檢查。
- 只允許明確唯讀功能碼：FC01、02、03、04、07、11、12、17、20、24、43。
- FC43 只允許完整的 MEI 0x0E Read Device Identification。
- 必須恰好是一個完整 MBAP ADU，protocol ID 必須為 0，宣告長度必須與實際長度一致。
- 寫入功能碼、未知功能碼、尾隨/串接 ADU 或畸形 framing 會保存為
  `blocked-by-safety-policy`，不會傳送。
- `length` strategy 適合離線 corpus/decoder 測試；其畸形 MBAP length 在 `--execute` 時
  預期會被封鎖。

若要主動執行，建議先使用 `boundary`、`semantic`、`transaction` 或 `unit-id` 等仍能保持
單一完整 ADU 的策略，並從少量案例與低速率開始。

## 9. 常見問題

### 顯示 `configured`，沒有變成 `confirmed`

- 確認角色埠是否正確，例如非標準 Modbus 必須用 `--modbus-port`。
- 上層協定探測需要 `--max-layer 2` 以上。
- 目標可能只接受特定 Unit ID，或 response 結構/transaction correlation 無效。
- 任意 banner、echo 或只有 UDP 證據不會確認 TCP 協定。

### 報告沒有 fuzz candidate

查看 `port_summary.fuzz_candidates` 與 502/自訂埠的 finding。必須是 confirmed Modbus，而非
只有 open 或 port-hint。也要確認 `port_summary.scan_complete=true`。

### `BUDGET_EXCEEDED`

已完成的埠會保留，未嘗試的埠會是 `not-scanned`，但整份報告不會自動交給 fuzz。確認授權
範圍後，可提高 `--packet-budget`、選擇較高 profile，或縮小 `--ports` 的額外範圍；預設
catalog 仍會保留。不要把 `not-scanned` 當成 closed。

### `multiple eligible Modbus/TCP ports`

用錯誤訊息列出的候選埠搭配 `fuzz --scan-report ... --port PORT`，不要讓工具猜測。

### `scan-report Modbus preflight failed`

代表掃描後 endpoint 狀態改變、Unit ID 不正確、服務不再是 Modbus、response framing 無效，
或網路不可達。preflight 失敗時不會送 fuzz cases。

### 為什麼 `length` cases 全部是 blocked

這是安全邊界的預期行為。案例仍會保存在 report 供離線 parser/decoder 分析，但畸形 MBAP
framing 不會跨過主動傳輸邊界。

## 10. Exit code

| Exit code | 意義 |
| ---: | --- |
| 0 | 命令完成；網路命令仍應檢查 JSON 內的 status |
| 2 | 參數、檔案、解析、安全 policy 或執行錯誤 |
| 3 | `scan` 分類衝突，或 network-action budget 造成掃描不完整 |

自動化程式應同時檢查 exit code、`status`、`port_summary.scan_complete` 與
`port_summary.fuzz_candidates`。

## 11. 執行前後檢查表

執行前：

1. 確認書面授權、目標 IP、port、Unit ID 與測試時段。
2. 確認 PLC 不控制生產設備，或已有安全停機/隔離措施。
3. 建立快照或可驗證的復原方式。
4. 保存一筆事先選定、已知正常的唯讀 FC03 baseline response、服務日誌與必要的 PCAP。
5. 離線產生 corpus，人工確認 seed、策略、案例數、rate 與 target。

執行後：

1. 再次執行既定 health check。
2. 比對服務狀態、PLC application/OS 日誌與 process restart。
3. 不要把單次 timeout 直接宣稱為 crash 或漏洞。
4. 復原測試資料或快照，保存不含憑證與敏感製程資訊的報告。

完整 CLI 參數請見 [`modbus-cli.md`](modbus-cli.md)，探測層與 OpenPLC 判定限制請見
[`openplc-fingerprinting.md`](openplc-fingerprinting.md)，fuzz 結果判讀請見
[`fuzzing.md`](fuzzing.md)。
