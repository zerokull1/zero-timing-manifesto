#!/usr/bin/env python3
"""Zero-Timing Manifesto: Zero-dependency Python ctypes/mmap telemetry reader."""

import ctypes
import mmap
import os
import struct

ZERORING_MAGIC = 0x5A45524F52494E47


class ZeroRingHeader(ctypes.Structure):
    _align_ = 64
    _fields_ = [
        ("magic", ctypes.c_uint64),
        ("version", ctypes.c_uint32),
        ("capacity", ctypes.c_uint32),
        ("write_idx", ctypes.c_uint64),
        ("drop_count", ctypes.c_uint64),
        ("reserved", ctypes.c_uint8 * 32),
    ]


class ZeroRingSlot(ctypes.Structure):
    _align_ = 64
    _fields_ = [
        ("tsc_timestamp", ctypes.c_uint64),
        ("iat_cycles", ctypes.c_uint64),
        ("flow_hash", ctypes.c_uint32),
        ("payload_len", ctypes.c_uint16),
        ("l7_proto", ctypes.c_uint8),
        ("verdict", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 40),
    ]


def read_shm_header(shm_path: str = "/dev/shm/ZERORING") -> dict:
    if not os.path.exists(shm_path):
        return {"status": "offline", "path": shm_path}
    with open(shm_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), ctypes.sizeof(ZeroRingHeader), access=mmap.ACCESS_READ)
        hdr = ZeroRingHeader.from_buffer_copy(mm)
        mm.close()
    return {
        "status": "active" if hdr.magic == ZERORING_MAGIC else "uninitialized",
        "magic": hex(hdr.magic),
        "version": hdr.version,
        "capacity": hdr.capacity,
        "write_idx": hdr.write_idx,
        "drop_count": hdr.drop_count,
    }


if __name__ == "__main__":
    print("[Zero-Timing Python Bridge]", read_shm_header())
