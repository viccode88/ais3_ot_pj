# OpenPLC v3/v4 版本探測工具

`plcfp` 是與 `modbus_cli` 分離的 Python 套件。兩者沒有 import 關係；安裝同一個 wheel 只是方便
在目前 repository 發布。工具一次只接受一個明確 target，預設拒絕公網位址，並將每次網路
動作計入硬性封包預算。

## 快速開始

```bash
python3.11 -m pip install -e .
plcfp signatures
plcfp scan 10.20.30.40 --profile safe --max-layer 2 --output report.json
plcfp scan 10.20.30.40 --profile standard --max-layer 4 --format sarif
plcfp pcap plant-span.pcap --target 10.20.30.40 --output passive.json
```

同一主機需要多套 lab 時，可用 `--modbus-port`、`--v3-http-port`、`--v4-https-port`、
`--enip-port`、`--dnp3-port`、`--opcua-port` 覆寫每種協定的目的埠。實際官方 v3 Docker
lab 與驗證結果見 [`../lab/openplc-v3/README.md`](../lab/openplc-v3/README.md)。

只有隔離實驗室可使用 DNP3 主動探測，而且必須同時明確指定 profile 與 outstation 位址：

```bash
plcfp scan 10.20.30.40 --profile lab --dnp3-address 1
```

## 探測層與安全界線

- L0：讀取 classic Ethernet PCAP，辨識 v3 HTTP、v4 API/Socket.IO 路徑及通訊對象；不送封包。
- L1：TCP connect 與原始 TLS 握手，擷取 DER 憑證、DN、效期、SAN、雜湊、協定與 cipher。
- L2：v3/v4 未認證 HTTP、Engine.IO、FC43、ENIP ListIdentity、OPC UA Hello。
- L3：唯讀 Modbus 功能碼 bitmap、Unit ID、位址邊界與 30 次時序統計。
- L4：執行目前所有不需憑證且不改變 PLC 狀態的查詢。工具不猜測帳密，也不自動呼叫
  `/api/create-user`。

`safe` 的預設間隔為 500 ms、預算 60；`standard` 為 200 ms、預算 300；`lab` 為
50 ms、預算 1000。逾時預設 10 秒。`--packet-budget` 是硬限制，達到時報告狀態會是
`BUDGET_EXCEEDED`。DNP3 在沒有 `--profile lab --dnp3-address N` 時只記錄 TCP 埠狀態。

目前 OPC UA 模組執行標準 Hello/Acknowledge 探索；不把 Hello 冒充為 GetEndpoints。
TLS 模組記錄實際 cipher/協定，但不把它冒充完整 JARM。兩者可由後續簽章資料或專用探測器
擴充，不影響 v3/v4 的 HTTP/TLS 主判定功能。

## 判定與輸出

JSON 報告保留 `observations`（含 `available`、`state`、延遲與原始回應）、命中的
`evidence`、權重、版本區間、衝突、組態風險、生命週期、封包數及簽章資料庫版本。

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
