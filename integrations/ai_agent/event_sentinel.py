#!/usr/bin/env python3
"""
Zero-Polling Event-Driven AI Sentinel (eBPF RingBuf + epoll).
Consumes 0.0% CPU/GPU when idle; wakes up instantly on kernel XDP alerts.
"""
import ctypes, mmap, os, select, socket, struct, subprocess, urllib.request, json

SYS_BPF = 321
BPF_OBJ_GET = 7
RING_PATH = b"/sys/fs/bpf/zero_shield/events_ring\x00"
RING_SIZE = 4096 * 16  # Должен совпадать с max_entries в zero_dynamic_shield.c
ZERO_CTL = "./target/release/zero-ctl"

# Опциональный URL локальной LLM (например, Ollama: http://127.0.0)
LLM_ENDPOINT = os.environ.get("ZERO_AI_URL", "")
LLM_MODEL = os.environ.get("ZERO_AI_MODEL", "llama3")

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

class BpfObjAttr(ctypes.Structure):
    _fields_ = [("pathname", ctypes.c_uint64), ("bpf_fd", ctypes.c_uint32), ("file_flags", ctypes.c_uint32)]

def open_ringbuf_fd() -> int:
    buf = ctypes.create_string_buffer(RING_PATH)
    attr = BpfObjAttr(ctypes.addressof(buf), 0, 0)
    fd = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_int(BPF_OBJ_GET), ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)))
    if fd < 0:
        raise RuntimeError(f"Cannot open {RING_PATH.decode()} (errno={ctypes.get_errno()}). Run kpp_up.sh as root.")
    return int(fd)

def ask_ai_or_auto_mitigate(src_ip: str, reason: str):
    print(f"[ALERT] Kernel XDP trigger -> SRC={src_ip} | REASON={reason}", flush=True)
    if LLM_ENDPOINT:
        prompt = f"XDP firewall alert: IP {src_ip} triggered {reason}. Suggest one short mitigation action."
        try:
            req = urllib.request.Request(
                LLM_ENDPOINT,
                data=json.dumps({"model": LLM_MODEL, "prompt": prompt, "stream": False}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                reply = json.loads(resp.read().decode()).get("response", "").strip()
                print(f"[AI-DECISION] {reply}", flush=True)
        except Exception as e:
            print(f"[AI-FALLBACK] LLM unreachable ({e}), applying deterministic rule.", flush=True)

    # Пример детерминированной реакции: зажимаем лимит или читаем сводку через 5.7KB zero-ctl
    if os.path.exists(ZERO_CTL):
        out = subprocess.check_output([ZERO_CTL, "stats"], text=True).strip().replace("\n", " | ")
        print(f"[KPP-STATS] {out}", flush=True)

def main():
    fd = open_ringbuf_fd()
    page_size = mmap.PAGESIZE
    # В Linux eBPF ringbuf: 1-я страница = consumer_pos (RW), 2-я = producer_pos (RO), далее 2x RING_SIZE данных
    cons_mm = mmap.mmap(fd, page_size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
    prod_mm = mmap.mmap(fd, page_size + 2 * RING_SIZE, mmap.MAP_SHARED, mmap.PROT_READ, offset=page_size)

    ep = select.epoll()
    ep.register(fd, select.EPOLLIN)
    print("[OK] Event-Driven AI Sentinel sleeping on epoll_wait (0% CPU until XDP alert)...", flush=True)

    mask = RING_SIZE - 1
    while True:
        ep.poll()  # Спим без расхода CPU до аппаратного/ядерного события из XDP
        cons_pos = struct.unpack_from("<Q", cons_mm, 0)[0]
        prod_pos = struct.unpack_from("<Q", prod_mm, 0)[0]

        while cons_pos < prod_pos:
            hdr_off = page_size + (cons_pos & mask)
            rec_len, _pg_off = struct.unpack_from("<II", prod_mm, hdr_off)
            # Бит BPF_RINGBUF_BUSY_BIT (1 << 31) означает, что ядро ещё дописывает запись
            if rec_len & (1 << 31):
                break
            aligned_len = (rec_len + 7) & ~7
            if not (rec_len & (1 << 30)):  # Не BPF_RINGBUF_DISCARD_BIT
                _ts, ip_be, reason_id = struct.unpack_from("<QII", prod_mm, hdr_off + 8)
                src_ip = socket.inet_ntoa(struct.pack("<I", ip_be))
                reason = "RATE_FLOOD" if reason_id == 2 else "TTL_ANOMALY"
                ask_ai_or_auto_mitigate(src_ip, reason)
            cons_pos += 8 + aligned_len
            struct.pack_into("<Q", cons_mm, 0, cons_pos)

if __name__ == "__main__":
    main()
