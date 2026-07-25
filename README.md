# Modbus Lab CLI

`modbus-cli` 是以 Python 3.11+ 實作、面向**完全隔離且已授權實驗室**的 Modbus TCP
協議測試框架。核心 MBAP/PDU codec 為本地實作；傳輸、fuzz、插件和 CVE 行為回歸介面彼此
分離。它不是掃描器或 exploitation framework，也不會把單次逾時宣稱為漏洞。

## 功能與限制

- 建立、最佳努力解析及傳送功能碼 01/02/03/04/05/06/0F/10。
- 高階 read、寫入預覽（預設禁止寫入）、單一目標 probe。
- 九種 deterministic fuzz 策略；預設僅產生 corpus，必須加 `--execute` 才會傳送。
- JSON 案例、replay、保守異常分類及基礎結構最小化。
- 私有/loopback allowlist、速率/案例/並行上限、Python entry-point 插件 API。
- 初版僅支援 IPv4 Modbus TCP、每次請求重新連線。RTU、ASCII、TLS、序列排程、JUnit、
  完整 delta-debugging 與 CVE 實例尚未實作；介面保留於 transport/plugin/regression 邊界。

## 安裝

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
modbus-cli --help
```

## 可執行範例

```bash
modbus-cli version
modbus-cli info
modbus-cli build --function 3 --address 0 --quantity 10 --output json
modbus-cli decode --hex 00010000000601030000000A
modbus-cli read holding-registers --target 127.0.0.1 --port 1502 --address 0 --quantity 10
modbus-cli write single-register --target 127.0.0.1 --port 1502 --address 1 --values 1234 --dry-run
modbus-cli fuzz --target 127.0.0.1 --port 1502 --strategy boundary --strategy length --requests 100 --rate 10 --seed 12345
# 也可用秒數直接指定每次 fuzz 傳送的間隔（與 --rate 二擇一）
modbus-cli fuzz --target 127.0.0.1 --requests 10 --interval 0.5 --execute
modbus-cli replay artifacts/fuzz-report.json --times 3 --interval 1
modbus-cli minimize artifacts/fuzz-report.json
modbus-cli config init --file lab.toml
modbus-cli config validate --file lab.toml
modbus-cli plugins list
```

相同 seed、策略次序與案例數會產生相同 request。`fuzz` 不加 `--execute` 是安全的離線
產生模式。寫入目前 fail-closed：`--dry-run` 可預覽；核心預設 policy 不允許真的寫入。

## 安全操作與 OpenPLC

預設只允許 loopback、RFC1918 私網；DNS 會先解析再套用 policy。工具只接受單一 target，沒有
網段掃描。請用獨立 VLAN/host-only 網路、快照和明確測試位址。完整程序見
[`docs/openplc-lab.md`](docs/openplc-lab.md)。封包可能造成 PLC 服務失效；切勿連至生產環境。

## 設定、報告與插件

TOML 設定命令可建立/檢查安全設定；目前 CLI 的操作參數仍以命令列為準，完整分層合併列入
roadmap。fuzz 報告為 JSON 並保留 seed、mutation、request/response、延遲、狀態與保守分類。
插件使用 `modbus_cli.plugins` entry-point，規格及範例見
[`docs/plugin-development.md`](docs/plugin-development.md)。CVE 模組僅用於 patch/行為回歸，見
[`docs/cve-module-development.md`](docs/cve-module-development.md)。

## 開發與測試

```bash
ruff check .
ruff format --check .
mypy src
pytest
pytest --cov=modbus_cli --cov-report=term-missing
```

OpenPLC 測試預設跳過；未來顯式配置實驗室後以 `pytest -m openplc` 執行。架構與 fuzz 說明見
[`docs/architecture.md`](docs/architecture.md) 和 [`docs/fuzzing.md`](docs/fuzzing.md)。

## 獨立 OpenPLC 版本探測器

repository 另含獨立的 `plcfp` 套件；它不匯入 `modbus_cli`，可主動判別 OpenPLC Runtime
v3/v4、輸出版本區間與證據鏈，也可離線分析 PCAP。安全分級、硬性封包預算、TLS/HTTP、
Socket.IO、唯讀 Modbus、ENIP、OPC UA 與 lab-only DNP3 的操作方式見
[`docs/openplc-fingerprinting.md`](docs/openplc-fingerprinting.md)。

### 實際搭建 OpenPLC v3 並探測

lab 使用官方 archived `OpenPLC_v3` commit
`b5d41356dab4aeadca0dd7ca64ba542f870b595d`，所有服務只綁在 loopback。預設映射為：

- Modbus TCP：`127.0.0.1:1502 → container:502`
- HTTP UI：`127.0.0.1:18080 → container:8080`
- EtherNet/IP：`127.0.0.1:14418 → container:44818`（TCP 與 UDP）

建置、啟動 Runtime：

```bash
docker compose -f lab/openplc-v3/compose.yaml build
docker compose -f lab/openplc-v3/compose.yaml up -d
curl -I http://127.0.0.1:18080/login
lab/openplc-v3/start-runtime.sh
```

先用保守模式確認主版本：

```bash
plcfp scan 127.0.0.1 \
  --profile safe \
  --max-layer 2 \
  --modbus-port 1502 \
  --v3-http-port 18080 \
  --enip-port 14418 \
  --no-raw
```

再執行完整的 standard/L4 唯讀探測並保存報告：

```bash
plcfp scan 127.0.0.1 \
  --profile standard \
  --max-layer 4 \
  --modbus-port 1502 \
  --v3-http-port 18080 \
  --enip-port 14418 \
  --no-raw \
  --output openplc-v3-report.json
```

2026-07-25 對上述固定 commit 的實測摘要：

```json
{
  "product": "OpenPLC Runtime",
  "major": "v3",
  "version_range": {"min": null, "max": null},
  "point_estimate": null,
  "build_epoch": "epoch≈2025-Q4 (v3 release marker)",
  "confidence": 0.896,
  "lifecycle": "end-of-life",
  "status": "complete",
  "packets_sent": 144
}
```

同次探測確認 FC43 回傳例外碼 `01`、Unit ID `0/1/247/255` 全部有回應、唯讀功能碼
bitmap 為 `0x1e`，位址上界為 `(8184, 8184, 1023, 8191)`。ENIP `ListIdentity` 沒有回應，
但 `RegisterSession` 成功；工具會把這種「負面＋正面」組合完整保留，而不是視為掃描失敗。
可重現的完整摘要在
[`lab/openplc-v3/verified-result.json`](lab/openplc-v3/verified-result.json)，lab 細節見
[`lab/openplc-v3/README.md`](lab/openplc-v3/README.md)。

測試完成後停止並移除 lab 容器與網路（保留已建映像，方便下次啟動）：

```bash
docker compose -f lab/openplc-v3/compose.yaml down
```

## Roadmap、貢獻與授權

Roadmap：持久連線/分段時序、health-check orchestration、RTU/ASCII/TLS transports、完整
reporters、設定合併、經 replay 驗證的 delta debugging、mock server 整合矩陣。提交前請執行
上述四項檢查；新增 parser bug 時必須加入 regression assertion。安全問題請依
[`SECURITY.md`](SECURITY.md) 私下回報。MIT 授權，詳見 [`LICENSE`](LICENSE)。
