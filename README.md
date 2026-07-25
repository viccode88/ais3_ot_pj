# Modbus TCP 封包工具 (modbus_cli.py)

純 Python 標準函式庫實作，無需安裝任何套件。Python 3.7+。

## 用法

```bash
# 1. 啟動本機測試伺服器 (另開一個終端機)
python3 modbus_cli.py server --port 1502

# 2. 組裝並顯示封包 hex
python3 modbus_cli.py build -f 3 -a 0 -q 10

# 3. 送出封包並解析回應
# 讀取 5 個 holding registers
python3 modbus_cli.py send --host 127.0.0.1 --port 1502 -f 3 -a 0 -q 5
# 寫單一暫存器 (值 1234 到位址 1)
python3 modbus_cli.py send --host 127.0.0.1 --port 1502 -f 6 -a 1 -v 1234

# 4. 模糊測試
python3 modbus_cli.py fuzz --host 127.0.0.1 --port 1502 -n 200 -o report.json --verbose
```

## 子命令

| 命令     | 說明 |
|----------|------|
| `build`  | 組裝封包顯示 hex，加 `--send` 可直接送出 |
| `send`   | 送出封包並解析回應（含例外碼） |
| `fuzz`   | 模糊測試 |
| `server` | 啟動簡易 mock Modbus 伺服器供本機測試 |

## 支援的 function codes

1/2/3/4 讀取類，5/6 寫單一，15/16 寫多筆。

## 模糊測試三種層面

- **欄位值隨機化** (`-m fields`)：隨機 function code / address / quantity / values。
- **畸形/邊界封包** (`-m malformed`)：保留 function code、超大/為零的 quantity、截斷封包、MBAP length 造假、超長 payload、純亂數位元組。
- **回應紀錄** (`-o report.json`)：每個封包的送出內容、回應、例外碼、延遲全部記錄成 JSON 報告，逾時與連線錯誤會標記為異常。

`--seed` 可固定亂數以重現測試；`--delay` 控制發送間隔。

## ⚠️ 使用須知

Modbus 協定無認證機制，fuzz 可能造成設備停機或不可預期行為。**只可對你有權限、且位於隔離測試環境的裝置使用。**
