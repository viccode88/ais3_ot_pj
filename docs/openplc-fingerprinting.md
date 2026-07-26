# OpenPLC v3/v4 版本探測工具

`plcfp` 是 OpenPLC/PLC 服務探測核心；可由相容入口 `plcfp scan` 使用，也可由整合入口
`modbus-cli scan` 使用。工具一次只接受一個明確 target，預設拒絕公網位址，並將每次網路
probe/action 計入硬性 scheduler 預算。

需要從端口掃描一路交接到 Modbus fuzz 時，請使用
[`scan-to-fuzz.md`](scan-to-fuzz.md) 的完整端到端指南。

## 快速開始

```bash
python3.11 -m pip install -e .
plcfp signatures
plcfp scan 10.20.30.40 --profile safe --max-layer 2 --output report.json
plcfp scan 10.20.30.40 --ports 22,80,102,502,1217,4840,11740,44818 --format text
plcfp scan 10.20.30.40 --profile standard --max-layer 4 --format sarif
plcfp pcap plant-span.pcap --target 10.20.30.40 --output passive.json
```

`plcfp scan` 的完整語法：

```text
plcfp scan TARGET
  [--profile safe|standard|lab]
  [--max-layer 1|2|3|4]
  [--timeout SEC]
  [--interval SEC]
  [--packet-budget COUNT]
  [--allow-public]
  [--dnp3-address ADDRESS]
  [--modbus-port PORT]
  [--v3-http-port PORT]
  [--v4-https-port PORT]
  [--enip-port PORT]
  [--dnp3-port PORT]
  [--opcua-port PORT]
  [--ports SPEC]
  [--signature-dir DIR]
  [--format json|text|csv|sarif]
  [--output PATH]
  [--no-raw]
```

與整合入口的差異：

| 項目 | `plcfp scan` | `modbus-cli scan` |
| --- | --- | --- |
| Target 寫法 | positional `TARGET` | `--target HOST` |
| 預設 profile / layer | `standard` / L4 | `safe` / L2 |
| 自訂間隔 | `--interval` | `--scan-interval` |
| 公網選項 | 有 `--allow-public` | 無；固定使用私網 policy |

`--allow-public` 只解除程式的私網保護，不代表取得授權，也不降低對遠端 PLC 的操作風險。
除非測試範圍明確書面包含該位址且已有隔離、復原與觀測措施，否則不要使用。

掃描器預設包含常見 PLC/ICS TCP 埠與管理介面（例如 102、502、1217、4840、11740、
20000、44818、80/443/8080/8443）；`--ports` 可加入逗號清單或範圍，但每次最多展開
1024 個額外埠，不會預設掃描 1–65535。

同一主機需要多套 lab 時，可用 `--modbus-port`、`--v3-http-port`、`--v4-https-port`、
`--enip-port`、`--dnp3-port`、`--opcua-port` 改變每種協定的主動 probe 目的埠。標準
catalog 埠不會因此移除；例如指定 `--modbus-port 1502` 後，502 仍會做 TCP connect 並保留
port-hint。實際官方 v3 Docker lab 與驗證結果見
[`../lab/openplc-v3/README.md`](../lab/openplc-v3/README.md)。

只有隔離實驗室可使用 DNP3 主動探測，而且必須同時明確指定 profile 與 outstation 位址：

```bash
plcfp scan 10.20.30.40 --profile lab --dnp3-address 1
```

## 探測層與安全界線

- L0：讀取 classic Ethernet PCAP，辨識 v3 HTTP、v4 API/Socket.IO 路徑及通訊對象；不送封包。
- L1：對 catalog/角色埠逐一 TCP connect。若 v4 HTTPS 角色埠開放，另做 TLS handshake，
  擷取 DER 憑證、DN、效期、SAN、雜湊、協定與 cipher。
- L2：對開放角色埠執行 v3 HTTP GET、v4 API GET、空 body `POST /api/login`、Engine.IO
  polling handshake、OPC UA Hello、Modbus FC43，以及 Unit ID 0/1/247/255 的 FC03 matrix。
  EtherNet/IP 在 safe profile 送 UDP ListIdentity；standard/lab 還會送 TCP
  RegisterSession、ListServices、ListInterfaces 與 NOP。
- L3：standard/lab 增加唯讀 Modbus 功能碼 bitmap、位址邊界查詢與 30 次時序統計；lab
  profile 且有 `--dnp3-address` 時可送 DNP3 Link Status。safe profile 不會因只提高 layer
  而啟用 standard/lab 的額外 Modbus probes。
- L4：目前沒有獨立於 L3 的額外 probe 模組，保留為最高層相容值。

空 login POST 不帶憑證或帳密，但可能留下失敗登入/audit log；Engine.IO polling handshake
可能在伺服器建立短暫 session；EtherNet/IP discovery 同時可能使用 UDP 與 TCP。工具不猜測
帳密、不自動呼叫 `/api/create-user`，也不送出設定變更 payload；但無法保證客製目標的
GET handler 完全沒有非標準副作用，因此仍須使用隔離環境。

`safe` 的預設間隔為 500 ms、預算 60；`standard` 為 200 ms、預算 300；`lab` 為
50 ms、預算 1000。逾時預設 10 秒。`--packet-budget` 是硬性 network-action 限制，達到時
報告狀態會是 `BUDGET_EXCEEDED`。歷史 JSON 欄位 `packets_sent` 也計算 scheduler actions，
不是 wire packets；一次 TCP/TLS/HTTP action 可能產生多個封包。DNP3 在沒有
`--profile lab --dnp3-address N` 時只記錄 TCP 埠狀態。

目前 OPC UA 模組執行標準 Hello/Acknowledge 探索；不把 Hello 冒充為 GetEndpoints。
TLS 模組記錄實際 cipher/協定，但不把它冒充完整 JARM。兩者可由後續簽章資料或專用探測器
擴充，不影響 v3/v4 的 HTTP/TLS 主判定功能。

## 判定與輸出

JSON 報告保留 `observations`（含 `available`、`state`、延遲與原始回應）、命中的
`evidence`、權重、版本區間、衝突、組態風險、生命週期、network-action 數（歷史欄位
`packets_sent`）及簽章資料庫版本。另有
`port_findings` 與 `port_summary`，直接列出服務候選、PLC 關聯度、辨識來源及 fuzz 資格。

- `plc_relevance=high` 表示該服務與 PLC/工控高度相關，不代表協定已確認。
- `identification=port-hint` 只根據常見/註冊埠推測。
- `identification=configured` 表示掃描器已把該埠設為某協定角色（預設或使用者覆寫），但
  probe 尚未確認。
- `identification=confirmed` 需要通過 request/response correlation 的有效上層協定 probe
  證據；任意 bytes、原樣 echo 或只有 UDP 證據都不會確認某個 TCP finding。
- 只有 `open + modbus-tcp + confirmed` 才會是 `fuzz_eligible=true`。
- `state=not-scanned` 表示硬性預算用盡前尚未探測，與已探測但失敗的 `unavailable` 分開。
- `port_summary.scan_complete` 表示整體掃描與上層 probe 是否在 network-action budget 內完成；
  即使 TCP 埠已掃完，上層 probe 耗盡 budget 仍會是 `false`。`status=INCONCLUSIVE` 則只
  表示 OpenPLC 世代未能判定，兩者語意不同。

[IANA Service Name and Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
明確提醒，註冊埠上有流量不代表它一定是被註冊的服務；因此報告刻意把關聯度與確認度
分開。`--format text` 會將高相關開放埠標為 `HIGH`，CSV 與 SARIF 也會保留 stable
`service_id`、替代候選、延遲及證據等 port finding 欄位。
PLC 專用候選埠另以 Siemens、Rockwell Automation 與 CODESYS 的官方產品文件交叉校正。

- `unavailable` 表示探測不到，絕不被當成特徵不存在。
- v3 只輸出 EOL 與建置/部署紀元線索，不製造 semver。
- v4 僅在規則有證據時收斂 semver 區間；沒有精確證據就不輸出 point estimate。
- v3、v4 強證據同時命中時輸出 `CONFLICT`，不強迫選邊。

簽章位於 `src/plcfp/signatures/*.yaml`，內容採 JSON（YAML 1.2 的嚴格子集），因此執行時不
依賴 PyYAML。可用 `--signature-dir` 載入外部更新，`plcfp signatures` 會先驗證 schema、
版本一致性、必要欄位及權重範圍。

## 已知限制與實驗室校正

細版本規則必須以多個 v4 tag、v3 時間切片及非 OpenPLC 對照組採集後才能提升為硬規則。
內附的 `maxPayload >= 4.1.3` 規則明確標示 provisional；未完成實驗室採集前不應作為唯一
CVE 判定依據。classic PCAP 解析器目前支援 Ethernet + IPv4/TCP，不支援 pcapng、IPv6 或
跨封包重組；這些情境應先由 Zeek/tshark 正規化。

## Exit code

| Exit code | 意義 |
| ---: | --- |
| 0 | 命令完成；仍應檢查 JSON `status`，主動 scan 另檢查 `port_summary.scan_complete` |
| 2 | 參數、檔案、解析、簽章或網路錯誤 |
| 3 | `scan`/`pcap` 分類衝突，或主動掃描因 network-action budget 中止 |
