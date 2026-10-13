#!/usr/bin/env python3
"""Logging iSCSI proxy: listen on 127.0.0.1:3260, forward to 127.0.0.1:3261.

Prints a one-line summary per iSCSI PDU in each direction, with the CDB (for
SCSI commands), the status/response bytes (for SCSI responses), and the first
bytes of the data segment.  Used to see exactly what the Microsoft initiator
sends and how our target answers.
"""
import socket
import struct
import sys
import threading
import time

LISTEN = ("127.0.0.1", 3260)
UPSTREAM = ("127.0.0.1", 3261)

OPCODES = {
    0x00: "NOP-OUT", 0x01: "SCSI-CMD", 0x02: "TASK-MGMT-REQ", 0x03: "LOGIN-REQ",
    0x04: "TEXT-REQ", 0x05: "SCSI-DATA-OUT", 0x06: "LOGOUT-REQ", 0x10: "SNACK",
    0x20: "NOP-IN", 0x21: "SCSI-RESP", 0x22: "TASK-MGMT-RESP", 0x23: "LOGIN-RESP",
    0x24: "TEXT-RESP", 0x25: "SCSI-DATA-IN", 0x26: "LOGOUT-RESP", 0x31: "R2T",
    0x3f: "REJECT", 0x60: "ASYNC",
}


def pad4(n):
    return (n + 3) & ~3


class Log:
    def __init__(self):
        self.lock = threading.Lock()

    def __call__(self, msg):
        with self.lock:
            print(msg, flush=True)


log = Log()


START = time.time()


def summarize(direction, hdr, data):
    opcode = hdr[0] & 0x3F
    immed = (hdr[0] & 0x40) != 0
    flags = hdr[1]
    b2, b3 = hdr[2], hdr[3]
    dsl = struct.unpack(">I", hdr[4:8])[0]
    lun = hdr[8:16]
    itt = struct.unpack(">I", hdr[16:20])[0]
    name = OPCODES.get(opcode, f"0x{opcode:02x}")
    s = (f"{direction} {name:<14} flags=0x{flags:02x}{'I' if immed else ' '} "
         f"b2={b2:02x} b3={b3:02x} dsl={dsl} itt=0x{itt:08x} ")
    if opcode in (0x01,):  # SCSI Command
        exp_len = struct.unpack(">I", hdr[20:24])[0]
        cmdsn = struct.unpack(">I", hdr[24:28])[0]
        expstat = struct.unpack(">I", hdr[28:32])[0]
        cdb = hdr[32:48]
        cdb_len = (flags >> 0) & 0x00  # unused
        s += f"expLen={exp_len} CmdSN={cmdsn} ExpStatSN={expstat} CDB={' '.join(f'{b:02x}' for b in cdb[:10])}"
        if data:
            s += f" data[{len(data)}]={' '.join(f'{b:02x}' for b in data[:16])}"
    elif opcode in (0x05, 0x00):  # Data-Out / NOP-Out
        s += f" data[{len(data)}]"
    elif opcode in (0x21, 0x25):  # SCSI Response / Data-In
        statsn = struct.unpack(">I", hdr[24:28])[0]
        expcmdsn = struct.unpack(">I", hdr[28:32])[0]
        maxcmdsn = struct.unpack(">I", hdr[32:36])[0]
        extra = ""
        if opcode == 0x25:
            datasn = struct.unpack(">I", hdr[36:40])[0]
            boff = struct.unpack(">I", hdr[40:44])[0]
            extra = f" DataSN={datasn} off={boff}"
        else:
            extra = f" Response={b2} Status={b3}"
        s += f"StatSN={statsn} ExpCmdSN={expcmdsn} MaxCmdSN={maxcmdsn}{extra}"
        if data:
            s += f" data[{len(data)}]={' '.join(f'{b:02x}' for b in data[:96])}"
    elif opcode in (0x03, 0x23, 0x04, 0x24):  # login/text
        text = data.decode("latin1", "replace").replace("\x00", ",")
        s += f" text={text!r}"
    if len(data) > 96 and opcode not in (0x03, 0x23, 0x04, 0x24):
        s += " ..."
    return s


def pump(src, dst, direction, label):
    """Read iSCSI PDUs from src, log them, write them to dst."""
    buf = b""
    try:
        while True:
            while len(buf) < 48:
                chunk = src.recv(65536)
                if not chunk:
                    log(f"[{label} {time.time() - START:8.3f}s] {direction} connection closed (EOF)")
                    return
                buf += chunk
            hdr = buf[:48]
            ahs_len = hdr[4] * 4
            dsl = struct.unpack(">I", hdr[5:8] if False else hdr[4:8])[0]
            # BHS: TotalAHSLength is byte 4, DataSegmentLength is bytes 5..8
            ahs_len = hdr[4] * 4
            dsl = int.from_bytes(hdr[5:8], "big")
            need = 48 + pad4(ahs_len) + pad4(dsl)
            while len(buf) < need:
                chunk = src.recv(65536)
                if not chunk:
                    log(f"[{label}] {direction} connection closed mid-PDU")
                    return
                buf += chunk
            pdu, buf = buf[:need], buf[need:]
            data = pdu[48 + pad4(ahs_len):48 + pad4(ahs_len) + dsl]
            log(f"[{label} {time.time() - START:8.3f}s] " + summarize(direction, pdu, data))
            dst.sendall(pdu)
    except OSError as exc:
        log(f"[{label} {time.time() - START:8.3f}s] {direction} socket error: {exc}")


def handle(client, label):
    try:
        upstream = socket.create_connection(UPSTREAM)
    except OSError as exc:
        log(f"[{label}] cannot reach the target: {exc}")
        client.close()
        return
    t1 = threading.Thread(target=pump, args=(client, upstream, "C->T", label), daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client, "T->C", label), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()
    log(f"[{label}] session finished")


def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(LISTEN)
    server.listen(16)
    log(f"proxy listening on {LISTEN[0]}:{LISTEN[1]} -> {UPSTREAM[0]}:{UPSTREAM[1]}")
    n = 0
    while True:
        client, addr = server.accept()
        n += 1
        label = f"{n}"
        log(f"[{label} {time.time() - START:8.3f}s] connect from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle, args=(client, label), daemon=True).start()


if __name__ == "__main__":
    main()
