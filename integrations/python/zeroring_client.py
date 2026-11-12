#!/usr/bin/env python3
"""
Zero-Timing Manifesto v1.1.0-beta — Zero-Copy Python SDK (ctypes / mmap)
Чтение телеметрии ZERORING и управление контуром Active Defense (Ловушки и MTD).
"""
import ctypes
import mmap
import os
import socket
import struct

ZERORING_MAGIC = 0x5A45524F52494E47
VERDICT_NAMES = {
    0: "DROP",
    1: "PASS",
    2: "DECEPTION_TRAP",
    3: "MTD_MUTATE",
}

DEFENSE_TRAP_ENABLE = 1 << 0
DEFENSE_MTD_ENABLE  = 1 << 1
DEFENSE_STRICT_L7   = 1 << 2


class ZeroRingClient:
    HEADER_FMT = "<QIIQQQIIH14s"
    HEADER_SIZE = 64

    def __init__(self, shm_path: str = "/dev/shm/ZERORING", so_path: str = None):
        self.shm_path = shm_path
        self.lib = ctypes.CDLL(so_path) if so_path and os.path.exists(so_path) else None
        if self.lib:
            self.lib.zero_cisco_inspect_frame.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
            self.lib.zero_cisco_inspect_frame.restype = ctypes.c_uint32

    def read_header(self) -> dict:
        if not os.path.exists(self.shm_path):
            raise FileNotFoundError(f"Shared memory ring not found: {self.shm_path}")
        with open(self.shm_path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), self.HEADER_SIZE)
            raw = mm.read(self.HEADER_SIZE)
            mm.close()
        magic, ver, cap, w_idx, drops, traps, mtd_epoch, flags, ent_x100, _ = struct.unpack(self.HEADER_FMT, raw)
        if magic != ZERORING_MAGIC:
            raise ValueError(f"Invalid ZERORING magic: {hex(magic)}")
        return {
            "abi_version": hex(ver),
            "capacity": cap,
            "write_idx": w_idx,
            "drop_count": drops,
            "trap_count": traps,
            "mtd_epoch": mtd_epoch,
            "defense_flags": flags,
            "entropy_threshold": ent_x100 / 100.0,
        }

    def set_active_defense_shm(self, trap: bool = True, mtd: bool = True, strict_l7: bool = False, entropy_threshold: float = 7.50, mtd_epoch: int = 1):
        """Атомарное обновление политик ловушек и MTD-мутации напрямую в ZERORING SHM."""
        flags = (DEFENSE_TRAP_ENABLE if trap else 0) | (DEFENSE_MTD_ENABLE if mtd else 0) | (DEFENSE_STRICT_L7 if strict_l7 else 0)
        ent_x100 = int(round(entropy_threshold * 100))
        with open(self.shm_path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), self.HEADER_SIZE)
            mm.seek(40)  # смещение полей mtd_epoch, defense_flags, entropy_threshold_x100
            mm.write(struct.pack("<IIH", mtd_epoch, flags, ent_x100))
            mm.flush()
            mm.close()


    def add_whitelist_cidr(self, cidr: str) -> bool:
        """Добавляет доверенную подсеть (например, 10.0.0.0/8) в lock-free IPv4 Whitelist."""
        if not self.lib:
            raise RuntimeError("C-ABI shared library (.so) not loaded")
        ip_str, prefix_str = cidr.split("/")
        prefix = int(prefix_str)
        net_be = struct.unpack("!I", socket.inet_aton(ip_str))
        mask_be = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix > 0 else 0
        self.lib.zero_cisco_add_whitelist.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        self.lib.zero_cisco_add_whitelist.restype = ctypes.c_uint32
        return self.lib.zero_cisco_add_whitelist(net_be, mask_be) == 1

    def inspect_packet(self, payload: bytes) -> str:
        if not self.lib:
            raise RuntimeError("C-ABI shared library (.so) not loaded")
        buf = (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload)
        verdict = self.lib.zero_cisco_inspect_frame(buf, len(payload))
        return VERDICT_NAMES.get(verdict, f"UNKNOWN({verdict})")


if __name__ == "__main__":
    print("Zero-Timing Python SDK v1.1.0-beta готов. Доступные вердикты:", VERDICT_NAMES)
