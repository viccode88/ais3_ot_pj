#!/usr/bin/env python3
"""
modbus_cli.py — Modbus TCP 封包產生 / 送出 / 模糊測試 CLI 工具

僅使用 Python 標準函式庫，無需安裝任何套件。

功能:
  build   組裝並顯示一個 Modbus TCP 封包 (hex)，可選擇送出
  send    連線目標裝置、送出封包並解析回應
  fuzz    模糊測試: 欄位值隨機化 / 畸形邊界封包 / 回應紀錄報告
  server  啟動一個簡易 mock Modbus 伺服器 (供本機測試用)

⚠️ 僅可對你有權限測試的裝置使用。Modbus 無認證機制，
   對正式運轉中的工控設備進行 fuzz 可能造成停機或危害，請務必在
   隔離的測試環境操作。
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Modbus 常數
# ---------------------------------------------------------------------------

FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}

EXCEPTION_CODES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Slave Device Failure",
    5: "Acknowledge",
    6: "Slave Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond",
}

MODBUS_PORT = 502


# ---------------------------------------------------------------------------
# 封包編碼 (MBAP header + PDU)
# ---------------------------------------------------------------------------

def build_pdu(function_code, address=0, quantity=1, values=None):
    """依 function code 組裝 PDU (function code + data)。"""
    fc = function_code
    if fc in (1, 2, 3, 4):
        # 讀取類: address(2) + quantity(2)
        return struct.pack(">BHH", fc, address, quantity)
    if fc == 5:
        # Write Single Coil: address(2) + value(2)，0xFF00=ON / 0x0000=OFF
        v = 0xFF00 if (values and values[0]) else 0x0000
        return struct.pack(">BHH", fc, address, v)
    if fc == 6:
        # Write Single Register: address(2) + value(2)
        v = (values[0] if values else 0) & 0xFFFF
        return struct.pack(">BHH", fc, address, v)
    if fc == 15:
        # Write Multiple Coils
        vals = values or [0]
        qty = len(vals)
        byte_count = (qty + 7) // 8
        coil_bytes = bytearray(byte_count)
        for i, bit in enumerate(vals):
            if bit:
                coil_bytes[i // 8] |= (1 << (i % 8))
        return struct.pack(">BHHB", fc, address, qty, byte_count) + bytes(coil_bytes)
    if fc == 16:
        # Write Multiple Registers
        vals = values or [0]
        qty = len(vals)
        byte_count = qty * 2
        body = struct.pack(">BHHB", fc, address, qty, byte_count)
        body += b"".join(struct.pack(">H", v & 0xFFFF) for v in vals)
        return body
    # 其他/未知 function code: 保留原始欄位當作通用讀取格式
    return struct.pack(">BHH", fc & 0xFF, address & 0xFFFF, quantity & 0xFFFF)


def build_adu(function_code, address=0, quantity=1, values=None,
              unit_id=1, transaction_id=1, pdu=None):
    """組裝完整 Modbus TCP ADU = MBAP header + PDU。"""
    if pdu is None:
        pdu = build_pdu(function_code, address, quantity, values)
    protocol_id = 0
    length = len(pdu) + 1  # +1 是 unit_id
    mbap = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
    return mbap + pdu


def parse_response(data):
    """解析 Modbus TCP 回應，回傳 dict。"""
    if len(data) < 8:
        return {"error": "回應過短", "raw": data.hex()}
    tid, pid, length, unit = struct.unpack(">HHHB", data[:7])
    fc = data[7]
    result = {
        "transaction_id": tid,
        "protocol_id": pid,
        "length": length,
        "unit_id": unit,
        "function_code": fc,
        "raw": data.hex(),
    }
    if fc & 0x80:  # 例外回應
        exc = data[8] if len(data) > 8 else None
        result["exception"] = True
        result["exception_code"] = exc
        result["exception_name"] = EXCEPTION_CODES.get(exc, "Unknown")
    else:
        result["exception"] = False
        result["function_name"] = FUNCTION_CODES.get(fc, "Unknown")
        result["data"] = data[8:].hex()
    return result


# ---------------------------------------------------------------------------
# 網路送出
# ---------------------------------------------------------------------------

def send_packet(host, port, packet, timeout=2.0, recv_size=4096):
    """建立 TCP 連線送出封包，回傳 (response_bytes, elapsed_seconds)。
    若無回應或連線失敗，response 為 None 並在 error 欄位標示。"""
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(packet)
            try:
                resp = s.recv(recv_size)
            except socket.timeout:
                resp = None
        return resp, time.time() - start, None
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return None, time.time() - start, str(e)


# ---------------------------------------------------------------------------
# 模糊測試
# ---------------------------------------------------------------------------

def mutate_fields(base):
    """欄位值隨機化: 隨機挑選 function code / address / quantity / value。"""
    fc = random.choice(list(FUNCTION_CODES.keys()))
    address = random.randint(0, 0xFFFF)
    quantity = random.randint(1, 125)
    values = [random.randint(0, 0xFFFF) for _ in range(random.randint(1, 8))]
    return build_adu(fc, address, quantity, values,
                     unit_id=base["unit_id"],
                     transaction_id=random.randint(0, 0xFFFF))


def mutate_malformed(base):
    """畸形 / 邊界封包: 產生違反規格的封包。"""
    strategy = random.choice([
        "reserved_fc",       # 保留/未定義 function code
        "oversized_qty",     # 超過合法上限的 quantity
        "zero_qty",          # quantity = 0
        "truncated",         # 截斷封包
        "bad_length",        # MBAP length 欄位與實際不符
        "huge_payload",      # 超長 payload
        "random_bytes",      # 完全亂數位元組
    ])
    tid = random.randint(0, 0xFFFF)
    unit = base["unit_id"]

    if strategy == "reserved_fc":
        fc = random.choice([0, 7, 8, 9, 65, 100, 127, 0x80, 0xFF])
        pkt = build_adu(fc, random.randint(0, 0xFFFF), 1,
                        unit_id=unit, transaction_id=tid,
                        pdu=struct.pack(">BHH", fc & 0xFF, 0, 1))
    elif strategy == "oversized_qty":
        pkt = build_adu(3, 0, 0xFFFF, unit_id=unit, transaction_id=tid)
    elif strategy == "zero_qty":
        pkt = build_adu(3, 0, 0, unit_id=unit, transaction_id=tid)
    elif strategy == "truncated":
        full = build_adu(3, 0, 10, unit_id=unit, transaction_id=tid)
        pkt = full[:random.randint(1, max(1, len(full) - 1))]
    elif strategy == "bad_length":
        pdu = build_pdu(3, 0, 10)
        fake_len = random.choice([0, 1, 0xFFFF, len(pdu) + 50])
        pkt = struct.pack(">HHHB", tid, 0, fake_len, unit) + pdu
    elif strategy == "huge_payload":
        n = random.randint(200, 2000)
        # byte_count 欄位僅 1 byte，故意讓它與實際超長 payload 不符 (畸形)
        byte_count = (n * 2) & 0xFF
        pdu = struct.pack(">BHHB", 16, 0, n & 0xFFFF, byte_count) + os.urandom(n * 2)
        pkt = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu
    else:  # random_bytes
        pkt = os.urandom(random.randint(4, 64))

    return pkt, strategy


def run_fuzz(args):
    base = {"unit_id": args.unit_id}
    if args.seed is not None:
        random.seed(args.seed)

    records = []
    modes = []
    if args.mode in ("fields", "all"):
        modes.append("fields")
    if args.mode in ("malformed", "all"):
        modes.append("malformed")

    print(f"[*] 開始模糊測試 -> {args.host}:{args.port}")
    print(f"[*] 模式: {', '.join(modes)}  迭代: {args.iterations}  "
          f"seed: {args.seed}\n")

    anomalies = 0
    for i in range(args.iterations):
        mode = random.choice(modes)
        strategy = mode
        if mode == "fields":
            pkt = mutate_fields(base)
        else:
            pkt, strategy = mutate_malformed(base)

        resp, elapsed, err = send_packet(args.host, args.port, pkt,
                                         timeout=args.timeout)
        rec = {
            "iteration": i,
            "mode": mode,
            "strategy": strategy,
            "sent": pkt.hex(),
            "sent_len": len(pkt),
            "elapsed_ms": round(elapsed * 1000, 2),
        }

        if err:
            rec["result"] = "error"
            rec["error"] = err
            anomalies += 1
            flag = "⚠ ERR"
        elif resp is None:
            rec["result"] = "no_response"
            rec["timeout"] = True
            anomalies += 1
            flag = "⚠ TIMEOUT"
        else:
            parsed = parse_response(resp)
            rec["result"] = "response"
            rec["response"] = parsed
            if parsed.get("exception"):
                flag = f"exc={parsed['exception_name']}"
            else:
                flag = "ok"

        records.append(rec)
        if args.verbose or rec["result"] in ("error", "no_response"):
            print(f"  #{i:<4} [{strategy:<14}] {rec['sent_len']:>4}B  "
                  f"{rec['elapsed_ms']:>7}ms  {flag}")

        if args.delay:
            time.sleep(args.delay)

    # 報告
    total = len(records)
    print(f"\n[*] 完成 {total} 次迭代，偵測到 {anomalies} 個可疑異常 "
          f"(逾時/連線錯誤)")
    excs = sum(1 for r in records
               if r.get("response", {}).get("exception"))
    print(f"[*] 目標回傳例外碼: {excs} 次")

    if args.output:
        report = {
            "target": f"{args.host}:{args.port}",
            "timestamp": datetime.now().isoformat(),
            "config": {
                "mode": args.mode, "iterations": args.iterations,
                "seed": args.seed, "unit_id": args.unit_id,
            },
            "summary": {
                "total": total, "anomalies": anomalies, "exceptions": excs,
            },
            "records": records,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[*] 報告已寫入: {args.output}")


# ---------------------------------------------------------------------------
# 簡易 mock 伺服器 (供本機測試)
# ---------------------------------------------------------------------------

def run_server(args):
    """極簡 Modbus TCP 伺服器: 回應讀取請求、對未知 function 回例外。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f"[*] Mock Modbus 伺服器監聽於 {args.host}:{args.port} (Ctrl-C 結束)")
    registers = [random.randint(0, 0xFFFF) for _ in range(256)]
    try:
        while True:
            conn, addr = srv.accept()
            with conn:
                data = conn.recv(4096)
                if not data or len(data) < 8:
                    continue
                try:
                    tid, pid, length, unit = struct.unpack(">HHHB", data[:7])
                    fc = data[7]
                except struct.error:
                    continue
                if fc in (1, 2, 3, 4) and len(data) >= 12:
                    addr_f, qty = struct.unpack(">HH", data[8:12])
                    if qty == 0 or qty > 125 or addr_f + qty > len(registers):
                        pdu = struct.pack(">BB", fc | 0x80, 2)  # illegal addr
                    else:
                        byte_count = qty * 2
                        body = b"".join(
                            struct.pack(">H", registers[addr_f + i])
                            for i in range(qty))
                        pdu = struct.pack(">BB", fc, byte_count) + body
                elif fc in (5, 6, 15, 16):
                    pdu = data[7:8] + data[8:12]  # echo 前 4 bytes
                else:
                    pdu = struct.pack(">BB", fc | 0x80, 1)  # illegal function
                resp = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu
                conn.sendall(resp)
    except KeyboardInterrupt:
        print("\n[*] 伺服器關閉")
    finally:
        srv.close()


# ---------------------------------------------------------------------------
# CLI 子命令處理
# ---------------------------------------------------------------------------

def cmd_build(args):
    values = args.values if args.values else None
    pkt = build_adu(args.function, args.address, args.quantity, values,
                    unit_id=args.unit_id, transaction_id=args.transaction_id)
    fc_name = FUNCTION_CODES.get(args.function, "Unknown/Custom")
    print(f"Function : {args.function} ({fc_name})")
    print(f"Address  : {args.address}")
    print(f"Quantity : {args.quantity}")
    print(f"Length   : {len(pkt)} bytes")
    print(f"Hex      : {pkt.hex()}")
    print(f"Bytes    : {' '.join(f'{b:02x}' for b in pkt)}")
    if args.send:
        resp, elapsed, err = send_packet(args.host, args.port, pkt,
                                         timeout=args.timeout)
        _print_response(resp, elapsed, err)


def cmd_send(args):
    values = args.values if args.values else None
    pkt = build_adu(args.function, args.address, args.quantity, values,
                    unit_id=args.unit_id, transaction_id=args.transaction_id)
    print(f"[>] 送出 ({len(pkt)}B): {pkt.hex()}")
    resp, elapsed, err = send_packet(args.host, args.port, pkt,
                                     timeout=args.timeout)
    _print_response(resp, elapsed, err)


def _print_response(resp, elapsed, err):
    if err:
        print(f"[!] 連線錯誤: {err}")
        return
    if resp is None:
        print(f"[!] 逾時，無回應 ({elapsed*1000:.1f}ms)")
        return
    parsed = parse_response(resp)
    print(f"[<] 回應 ({elapsed*1000:.1f}ms): {resp.hex()}")
    for k, v in parsed.items():
        if k != "raw":
            print(f"      {k}: {v}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Modbus TCP 封包產生 / 送出 / 模糊測試工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--host", default="127.0.0.1", help="目標 IP (預設 127.0.0.1)")
        sp.add_argument("--port", type=int, default=MODBUS_PORT, help="目標埠 (預設 502)")
        sp.add_argument("--unit-id", type=int, default=1, help="Unit/Slave ID (預設 1)")
        sp.add_argument("--timeout", type=float, default=2.0, help="逾時秒數")

    # build
    b = sub.add_parser("build", help="組裝封包並顯示 hex")
    add_common(b)
    b.add_argument("-f", "--function", type=int, required=True, help="function code")
    b.add_argument("-a", "--address", type=int, default=0, help="起始位址")
    b.add_argument("-q", "--quantity", type=int, default=1, help="數量")
    b.add_argument("-v", "--values", type=int, nargs="*", help="寫入值 (寫入類指令用)")
    b.add_argument("--transaction-id", type=int, default=1)
    b.add_argument("--send", action="store_true", help="組裝後直接送出")
    b.set_defaults(func=cmd_build)

    # send
    s = sub.add_parser("send", help="送出封包並解析回應")
    add_common(s)
    s.add_argument("-f", "--function", type=int, required=True)
    s.add_argument("-a", "--address", type=int, default=0)
    s.add_argument("-q", "--quantity", type=int, default=1)
    s.add_argument("-v", "--values", type=int, nargs="*")
    s.add_argument("--transaction-id", type=int, default=1)
    s.set_defaults(func=cmd_send)

    # fuzz
    fz = sub.add_parser("fuzz", help="模糊測試")
    add_common(fz)
    fz.add_argument("-n", "--iterations", type=int, default=100, help="迭代次數")
    fz.add_argument("-m", "--mode", choices=["fields", "malformed", "all"],
                    default="all", help="欄位隨機化 / 畸形封包 / 全部")
    fz.add_argument("--seed", type=int, default=None, help="亂數種子 (可重現)")
    fz.add_argument("--delay", type=float, default=0.0, help="每次迭代間隔秒數")
    fz.add_argument("-o", "--output", help="JSON 報告輸出路徑")
    fz.add_argument("--verbose", action="store_true", help="顯示每一次迭代")
    fz.set_defaults(func=run_fuzz)

    # server
    sv = sub.add_parser("server", help="啟動本機 mock Modbus 伺服器")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=1502)
    sv.set_defaults(func=run_server)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
