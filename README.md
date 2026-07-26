# Modbus Lab CLI

這個 repository 以 `modbus-cli` 提供整合的 PLC 服務掃描、Modbus TCP 封包操作與 fuzz
工作流；`plcfp` 保留為相容的進階 OpenPLC 指紋入口：

| 工具 | 用途 | 適合情境 |
| --- | --- | --- |
| `modbus-cli` | 掃描 PLC/ICS 服務、建立/解析/傳送 Modbus TCP 封包，以及受限 fuzz | 資產辨識、封包驗證、隔離實驗室測試 |
| `plcfp` | `scan` 的進階/相容入口，以及離線 PCAP 分析 | OpenPLC 版本證據採集 |

兩個工具都只應用在你擁有或明確獲准測試的隔離環境。請勿連到生產 PLC、公共 IP，或任何
可能控制實體設備的網路。

## 安裝

需求：Python 3.11 以上。

```bash
git clone https://github.com/viccode88/ais3_ot_pj.git
cd ais3_ot_pj
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

確認安裝成功：

```bash
modbus-cli --version
plcfp --version
```

如果 shell 找不到指令，請先確認虛擬環境已啟用；也可以改用：

```bash
python -m modbus_cli --help
python -m plcfp --help
```

開發者若還需要測試、格式化與型別檢查工具，請安裝：

```bash
python -m pip install -e '.[dev]'
```

## 五分鐘開始使用 `modbus-cli`

若要直接使用整合後的「多端口掃描 → 保存 JSON → 離線 fuzz → 審查後執行」流程，請見
[`docs/scan-to-fuzz.md`](docs/scan-to-fuzz.md)；該指南包含完整參數、輸出欄位、非標準埠、
狀態判讀、錯誤排查及可直接複製的端到端範例。

先用完全離線的指令熟悉封包格式。以下指令不會連線：

```bash
# 建立「從位址 0 讀取 10 個 holding registers」的 Modbus TCP request
modbus-cli build --function 3 --address 0 --quantity 10 --output json

# 解析十六進位封包
modbus-cli decode --hex 00010000000601030000000A
```

`build` 會輸出完整 ADU、十六進位內容與解析後欄位。上例的重要欄位如下：

```text
transaction_id = 1
unit_id        = 1
function_code = 3  (read-holding-registers)
address       = 0
quantity      = 10
hex           = 00010000000601030000000A
```

確認你已經有一台位於隔離網路的 Modbus TCP 測試設備後，再執行會連線的讀取：

```bash
modbus-cli read holding-registers \
  --target 192.168.56.10 \
  --port 502 \
  --unit-id 1 \
  --address 0 \
  --quantity 10
```

也可以先由整合掃描器找出並標記 PLC 相關服務：

```bash
modbus-cli scan \
  --target 192.168.56.10 \
  --ports 22,80,102,502,1217,4840,8080,11740,44818 \
  --format text
```

人類可讀表格會把高 PLC 關聯埠標為 `HIGH`，並分開顯示 `port-hint`、`configured` 與
`confirmed`。只有實際協定 probe 成功才會標成 `confirmed`；開放 502/tcp 本身不等於已確認
Modbus。

其中：

- `--target` 是單一 PLC 或模擬器的 IP/hostname，不接受網段。
- `--port` 預設為 `502`。
- `--unit-id` 預設為 `1`。
- `--address` 是封包中的零起算位址。設備文件的 `40001` 通常對應位址 `0`，但仍應以設備
  手冊為準。
- `--quantity` 是要讀取的 coil/register 數量。

先用 `probe` 做最小確認也可以；它會實際送出一次 FC03、位址 0、數量 1 的唯讀請求：

```bash
modbus-cli probe --target 192.168.56.10 --port 502 --unit-id 1
```

## 哪些指令會送出封包？

執行前請先看這張表：

| 指令 | 是否連線 | 說明 |
| --- | --- | --- |
| `version`、`info`、`build`、`decode` | 否 | 本機資訊或離線封包處理 |
| `config`、`plugins`、`minimize` | 否 | 本機檔案或套件資訊處理 |
| `write ... --dry-run` | 否 | 只顯示預計寫入的 request |
| `read`、`probe`、`send` | **是** | 呼叫後立即連線並送出封包 |
| `scan` | **是** | 對預設 PLC/ICS TCP 埠與 `--ports` 指定埠做連線/安全協定探測 |
| `fuzz` | 否 | 預設只產生 corpus/report |
| `fuzz --execute` | **是** | 逐一送出產生的 fuzz cases |
| `replay` | **是** | 唯讀安全檢查通過後立即重送，不需要額外的 `--execute` |
| `write ... --confirm` | 目前不會 | 預設 policy 仍會拒絕所有實際寫入 |

預設只允許 loopback 與 RFC1918 私有位址：

- `127.0.0.0/8`
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

hostname 會先解析成 IPv4 再套用限制。這不是授權機制；使用者仍需自行確認測試範圍。
`fuzz --execute` 與 `replay` 的唯讀安全檢查不會套用到 expert-level `send`；`send` 會原樣
傳送使用者提供的 ADU，包含寫入功能碼，因此使用前必須先用 `decode` 完整審查。

## 常見操作

### 建立不同功能碼的封包

```bash
# FC01：讀取 16 個 coils
modbus-cli build --function 1 --address 0 --quantity 16 --output hex

# FC06：建立寫入單一 register 的封包；只在本機產生，不會傳送
modbus-cli build --function 6 --address 1 --values 1234 --output json

# FC10 (十進位 16)：建立寫入三個 registers 的封包
modbus-cli build --function 16 --address 10 --values 100,200,0x1234 --output json
```

支援功能碼 01、02、03、04、05、06、0F（十進位 15）及 10（十進位 16）。命令列的
`--function` 使用十進位整數。

### 解析檔案

`--file` 讀取的是原始 binary，不是內含十六進位文字的 `.txt`：

```bash
modbus-cli decode --file request.bin --output json
```

### 傳送自訂封包

`send` 會立即傳送，使用前應先用 `decode` 檢查內容：

```bash
modbus-cli decode --hex 00010000000601030000000A
modbus-cli send \
  --target 192.168.56.10 \
  --port 502 \
  --hex 00010000000601030000000A
```

加上 `--no-response` 只代表送出後不等待回應，不代表離線模式。

### 預覽寫入

```bash
modbus-cli write single-register \
  --target 192.168.56.10 \
  --address 1 \
  --values 1234 \
  --dry-run
```

目前版本的 `write` 僅提供安全預覽。拿掉 `--dry-run` 後必須加 `--confirm`，但仍會被預設
policy 拒絕；設定檔中的 `allow_write_functions` 尚未連接到 CLI 執行路徑。

### 離線產生 fuzz corpus

```bash
modbus-cli fuzz \
  --target 192.168.56.10 \
  --port 502 \
  --strategy boundary \
  --strategy length \
  --requests 100 \
  --rate 10 \
  --seed 12345 \
  --output artifacts/fuzz-report.json
```

若先保存 JSON 掃描報告，fuzz 可安全接手唯一一個「已確認且可 fuzz」的 Modbus/TCP 埠：

```bash
modbus-cli scan \
  --target 192.168.56.10 \
  --modbus-port 1502 \
  --output artifacts/scan-report.json

modbus-cli fuzz \
  --scan-report artifacts/scan-report.json \
  --unit-id 1 \
  --strategy boundary \
  --strategy semantic \
  --requests 10 \
  --interval 1 \
  --seed 12345 \
  --output artifacts/fuzz-review.json
```

若報告沒有 confirmed Modbus、掃描因 network-action budget 中止，或有多個候選卻未用 `--port`
消歧義，handoff 會 fail closed。沒有 `--execute` 時仍只產生 corpus。
報告驅動的 `--execute` 會先以相同 `--unit-id` 多送一個唯讀 FC03 protocol-correlation
preflight，成功後等待一個 fuzz interval；
只有 request/response correlation 通過後才會送 fuzz cases。

沒有 `--execute` 時只產生 JSON，不會送出案例。即使是離線產生，`--target` 仍必須能解析且
位於允許的私有網段，因為目標會寫入 report。

檢查 JSON 和測試環境後，才在隔離實驗室顯式執行：

```bash
modbus-cli fuzz \
  --scan-report artifacts/scan-report.json \
  --unit-id 1 \
  --strategy boundary \
  --strategy semantic \
  --requests 10 \
  --interval 1 \
  --seed 12345 \
  --output artifacts/executed-report.json \
  --execute
```

`--execute` 不會讀取前一個 corpus 檔，而是依相同 scan report、Unit ID、策略順序、案例數
與 seed 重建同一組 deterministic cases；這些參數必須與人工審查時一致。

執行時終端會逐案顯示突變後實際送出的 request 類型，以及目標實際回傳的 normal、
exception、malformed 或 no-packet 類型，例如：

```text
[case-000001] TX request-type=read-holding-registers (FC 0x03); target=192.168.56.10:502; strategy=boundary
[case-000001] RX response-type=exception-response/read-holding-registers (FC 0x83, exception=illegal-data-address 0x02); status=response; elapsed_ms=1.234; classification=normal-or-exception-response
```

逐案資訊寫到 stderr，完成後 stdout 仍是可直接解析的 JSON 摘要；完整案例也會保存到
`--output` 指定的 report。

同一個 seed、策略順序與案例數會產生相同 request。`--rate 10` 表示每秒最多 10 個 request；
`--interval 0.5` 表示每次傳送間隔 0.5 秒，兩者不能同時使用。
主動執行只允許單一且長度一致的 MBAP ADU；寫入功能碼、串接 ADU、非 MEI 0x0E 的 FC43，
以及 `length` strategy 產生的畸形 framing 都會保留為 blocked case，但不會送出。

### 重播與最小化案例

```bash
# 注意：這行會立刻向 report 內記錄的 target 重送第一個案例
modbus-cli replay artifacts/fuzz-report.json --times 3 --interval 1

# 只做結構裁切，輸出 *-minimized.json，不會連線
modbus-cli minimize artifacts/fuzz-report.json
```

`minimize` 不是完整 delta debugging，也不會自動驗證裁切後案例；請人工檢查後再決定是否
replay。

完整的參數、輸出欄位、限制與錯誤排查請見
[`docs/modbus-cli.md`](docs/modbus-cli.md)。隔離實驗室的準備與收尾流程請見
[`docs/openplc-lab.md`](docs/openplc-lab.md)。

## OpenPLC v3/v4 版本探測

`modbus-cli scan` 整合了 `plcfp` 的主動探測；獨立的 `plcfp` 指令仍可直接使用。兩者一次
只接受一個 target，以安全分級、硬性 network-action 預算和證據鏈判別 OpenPLC Runtime
v3/v4；
`plcfp` 也可以離線分析 PCAP。

歷史參數名稱 `--packet-budget` 與 JSON 欄位 `packets_sent` 計算的是 scheduler 執行的網路
probe/action，不是封包擷取中可見的 TCP/IP packet 數；一次 HTTP、TLS 或 TCP action 可能
產生多個 wire packets。

```bash
# 檢查內建簽章資料庫
plcfp signatures

# 對單一私有位址做保守的 L1/L2 探測並保存報告
plcfp scan 192.168.56.10 \
  --profile safe \
  --max-layer 2 \
  --output openplc-report.json \
  --no-raw

# 離線分析 classic Ethernet PCAP
plcfp pcap plant-span.pcap \
  --target 192.168.56.10 \
  --output passive-report.json
```

探測層、profile、各協定連接埠、報告判讀與已知限制請見
[`docs/openplc-fingerprinting.md`](docs/openplc-fingerprinting.md)。

repository 也包含固定 commit 的 OpenPLC v3 Docker lab：

```bash
docker compose -f lab/openplc-v3/compose.yaml build
docker compose -f lab/openplc-v3/compose.yaml up -d
curl -I http://127.0.0.1:18080/login
lab/openplc-v3/start-runtime.sh
```

預設只綁定 loopback：

- Modbus TCP：`127.0.0.1:1502`
- HTTP UI：`127.0.0.1:18080`
- EtherNet/IP TCP/UDP：`127.0.0.1:14418`

詳細步驟、預期結果與停止方式請見
[`lab/openplc-v3/README.md`](lab/openplc-v3/README.md)。

## Vulnerability Reproduction Module

`modbus-cli vuln` 是獨立的漏洞重現與驗證模組。它不同於一般封包產生、協定測試及 fuzzing：每個案例都有隔離環境條件、baseline、實際動作紀錄、系統觀測、證據式 verdict 與復原驗證；既有命令路徑不含 CVE 特例，也不會自動選擇或執行案例。

目前內建案例為 `CVE-2025-53476`：OpenPLC_v3 revision `a931181e8b81e36fadf7b74d5cba99b73c3f6d58` 的 ModbusTCP connection resource exhaustion。

安全模型是 fail-closed：沒有任意 `--target`，只接受自己新建且標記為 `modbus-cli.vulnerability-case` 的 Docker 容器；Compose 使用案例專用 bridge network，且所有 host port 僅映射至 `127.0.0.1`，並限制 CPU、記憶體、PID 與容器內 `nofile`。不使用 host network、不改宿主機 `ulimit`/sysctl/firewall，也不會刪除現有專案容器或 network。每個連線（包括零 payload connect）都會留下 evidence。

標準生命週期為：載入案例 → 安全檢查 → 驗證環境 → 建立隔離 target → baseline → trigger → 觀測與合法 Modbus probe → 證據判定 → cleanup → 新容器 recovery probe → report。任何階段失敗後都會進入 cleanup。

結果可能是 `REPRODUCED`、`NOT_REPRODUCED`、`INCONCLUSIVE`、`ENVIRONMENT_ERROR`、`SAFETY_ABORTED`、`EXECUTION_ERROR` 或 `RECOVERY_FAILED`。`REPRODUCED` 必須同時有穩定 baseline、明確 FD/socket 資源累積、合法 probe 劣化、仍存活的 target，及以全新容器完成的復原；單一 timeout 絕不會直接算重現。

```bash
tool vuln list
tool vuln info CVE-2025-53476

# 不建立容器：顯示 revision、預計容器/network、步驟、timeout 與安全限制
tool vuln run CVE-2025-53476 --dry-run --report-dir ./reports --json

# Docker daemon 可用時的實際驗證與執行
tool vuln validate CVE-2025-53476 --environment docker --report-dir ./reports
tool vuln run CVE-2025-53476 \
  --environment docker --report-dir ./reports --timeout 120 \
  --max-connections 800 --batch-size 16 --probe-interval 0.1 \
  --connection-delay 0 --verbose --json

# 只調整本案例專用 target container，不改 host
tool vuln run CVE-2025-53476 \
  --target-nofile 96 --safety-reserve 2 \
  --max-connections 800 --verbose

# 預設就是貼近 advisory 的 no-payload connect/wait/client-close 策略
tool vuln run CVE-2025-53476 \
  --trigger-strategy advisory \
  --max-connections 800 --verbose

# OpenPLC v3 專用：重現舊腳本的 FC16 huge payload 路徑
tool vuln run CVE-2025-53476 \
  --trigger-strategy huge-payload \
  --max-connections 32 --verbose --json
```

`--max-connections` 是 bounded lifecycle 嘗試上限，仍會被案例絕對上限夾住；同時開啟或保留的 client socket 另由 `active_connection_limit = RLIMIT_NOFILE - baseline descriptors - safety reserve` 控制，並寫入 dry-run 與報告。這個分離是為了符合 CVE-2025-53476 advisory：多輪 no-payload connect/wait/client-close 可能重用 client fd，但 server 端 `CLOSE_WAIT`/fd 會逐步累積。`--target-nofile` 只會改本案例建立的 OpenPLC container `nofile`，允許範圍是 32..128；`--safety-reserve` 只會改本案例的 descriptor reserve，允許範圍是 1..32。`--trigger-strategy advisory` 只使用 no-payload connect、等待、client close，最後保留一條 no-payload socket；`mixed` 可用來少量混入 incomplete MBAP header 作比較，但不是預設。`--keep-environment` 只能保留本案例專用 Compose project；正常完成會刪除容器、network 與暫存狀態。

`--trigger-strategy huge-payload` 是 OpenPLC v3 隔離案例專用，移植舊腳本的
FC16 Write Multiple Registers malformed payload：quantity 200..2000、實際 body 為
`quantity * 2` bytes、1-byte `byte_count` 依舊 wrap，MBAP length 宣告完整 oversized
PDU。這條路徑不走一般 `fuzz --execute`，也不接受任意 target；verdict 會依 baseline
穩定性、huge payload 後合法 Modbus probe 劣化、target process 狀態、FD/socket 指標和
fresh recovery 判定。

每次 run 產生 `reports/<timestamp>_CVE-2025-53476/`。先讀 `summary.json` 的 verdict；`network-actions.jsonl` 保存完整 ADU/PDU、MBAP 欄位、回應和 socket error；`observations.jsonl` 是 timestamped FD/thread/socket/CPU/memory 序列（無法取得明確標為 `unavailable`）；`openplc.log`、`runner.log`、`timeline.jsonl` 與 `report.md` 提供人類與程式可讀的完整證據。

新增案例時，在 `src/modbus_cli/vulnerability_reproduction/cases/<case>/` 放置 `manifest.yaml` 與 `VulnerabilityCase` 插件，並在 registry 的內建載入點註冊。manifest 只描述產品、版本、限制和 required observations；網路操作與 verifier 留在 case 類別。新 verifier 應保存正常與異常證據、區分 `NOT_REPRODUCED` 和 `INCONCLUSIVE`，並以 fake socket/假環境涵蓋 timeout、中斷、cleanup 和 recovery；不得改變既有 `build`、`send`、`fuzz` 或 scan 的語意來遷就案例。

## 開發與測試

```bash
ruff check .
ruff format --check .
mypy src
pytest
pytest --cov=modbus_cli --cov-report=term-missing
```

其他開發文件：

- [`docs/scan-to-fuzz.md`](docs/scan-to-fuzz.md)：PLC 端口掃描與 scan → fuzz 完整操作指南
- [`docs/architecture.md`](docs/architecture.md)：程式邊界與架構
- [`docs/fuzzing.md`](docs/fuzzing.md)：fuzz 策略與結果判讀
- [`docs/plugin-development.md`](docs/plugin-development.md)：插件開發
- [`docs/cve-module-development.md`](docs/cve-module-development.md)：CVE 行為回歸模組
- [`CONTRIBUTING.md`](CONTRIBUTING.md)：貢獻規範
- [`SECURITY.md`](SECURITY.md)：安全回報方式

MIT 授權，詳見 [`LICENSE`](LICENSE)。
