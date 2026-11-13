#!/usr/bin/env python3
import ctypes, mmap, os, select, socket, struct, subprocess, urllib.request, json

SYS_BPF, BPF_OBJ_GET = 321, 7
RING_PATH = b"/sys/fs/bpf/zero_shield/events_ring\x00"
RING_SIZE = 4096 * 16
ZERO_CTL = "./target/release/zero-ctl"
LLM_URL = os.environ.get("ZERO_AI_URL", "")
LLM_MODEL = os.environ.get("ZERO_AI_MODEL", "llama3")

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

class BpfObjAttr(ctypes.Structure):
    _fields_ = [("pathname", ctypes.c_uint64), ("bpf_fd", ctypes.c_uint32), ("file_flags", ctypes.c_uint32)]

def open_ring() -> int:
    buf = ctypes.create_string_buffer(RING_PATH)
    attr = BpfObjAttr(ctypes.addressof(buf), 0, 0)
    fd = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_int(BPF_OBJ_GET), ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)))
    if fd < 0:
        raise RuntimeError(f"Cannot open ringbuf (errno={ctypes.get_errno()}). Run kpp_up.sh first.")
    return int(fd)

def handle_alert(src_ip: str, reason: str):
    print(f"[ALERT] XDP Trigger -> SRC={src_ip} | REASON={reason}", flush=True)
    if LLM_URL:
        try:
            payload = json.dumps({"model": LLM_MODEL, "prompt": f"XDP alert: {src_ip} ({reason}). Action?", "stream": False}).encode()
            req = urllib.request.Request(LLM_URL, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as r:
                print(f"[AI] {json.loads(r.read().decode()).get('response', '').strip()}", flush=True)
        except Exception as e:
            print(f"[AI-OFFLINE] {e}", flush=True)
    if os.path.exists(ZERO_CTL):
        stats = subprocess.check_output([ZERO_CTL, "stats"], text=True).strip().replace("\n", " | ")
        print(f"[STATS] {stats}", flush=True)

def main():
    fd, pg = open_ring(), mmap.PAGESIZE
    cons_mm = mmap.mmap(fd, pg, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
    prod_mm = mmap.mmap(fd, pg + 2 * RING_SIZE, mmap.MAP_SHARED, mmap.PROT_READ, offset=pg)
    ep = select.epoll()
    ep.register(fd, select.EPOLLIN)
    print("[OK] AI Sentinel sleeping on epoll_wait (0% CPU/GPU until XDP alert)...", flush=True)

    mask = RING_SIZE - 1
    while True:
        ep.poll()
        cons_pos = struct.unpack_from("<Q", cons_mm, 0)
        prod_pos = struct.unpack_from("<Q", prod_mm, 0)
        while cons_pos < prod_pos:
            off = pg + (cons_pos & mask)
            rec_len, _ = struct.unpack_from("<II", prod_mm, off)
            if rec_len & (1 << 31): break
            aligned = (rec_len + 7) & ~7
            if not (rec_len & (1 << 30)):
                _, ip_be, reason_id = struct.unpack_from("<QII", prod_mm, off + 8)
                handle_alert(socket.inet_ntoa(struct.pack("<I", ip_be)), "RATE_FLOOD" if reason_id == 2 else "TTL_ANOMALY")
            cons_pos += 8 + aligned
            struct.pack_into("<Q", cons_mm, 0, cons_pos)

if __name__ == "__main__":
    main()
