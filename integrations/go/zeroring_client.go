package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
)

const zeroRingMagic uint64 = 0x5A45524F52494E47 // "ZERORING"

func main() {
	shmPath := "/dev/shm/ZERORING"
	f, err := os.Open(shmPath)
	if err != nil {
		fmt.Printf("[Zero-Timing Go Bridge] status=offline path=%s\n", shmPath)
		return
	}
	defer f.Close()

	data, err := syscall.Mmap(int(f.Fd()), 0, 64, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		fmt.Printf("[Zero-Timing Go Bridge] mmap_error=%v\n", err)
		return
	}
	defer syscall.Munmap(data)

	magic := binary.LittleEndian.Uint64(data[0:8])
	version := binary.LittleEndian.Uint32(data[8:12])
	capacity := binary.LittleEndian.Uint32(data[12:16])
	writeIdx := binary.LittleEndian.Uint64(data[16:24])
	dropCount := binary.LittleEndian.Uint64(data[24:32])

	status := "uninitialized"
	if magic == zeroRingMagic {
		status = "active"
	}
	fmt.Printf("[Zero-Timing Go Bridge] status=%s version=%d capacity=%d write_idx=%d drops=%d\n",
		status, version, capacity, writeIdx, dropCount)
}
