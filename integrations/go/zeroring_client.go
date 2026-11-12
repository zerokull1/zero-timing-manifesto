package zeroring

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
)

const (
	ZeroRingMagic      uint64 = 0x5A45524F52494E47
	ZeroRingHeaderSize        = 64

	VerdictDrop   uint8 = 0
	VerdictPass   uint8 = 1
	VerdictTrap   uint8 = 2
	VerdictMutate uint8 = 3

	DefenseTrapEnable uint32 = 1 << 0
	DefenseMTDEnable  uint32 = 1 << 1
	DefenseStrictL7   uint32 = 1 << 2
)

// RingTelemetry отражает 64-байтный заголовок /dev/shm/ZERORING без аллокаций.
type RingTelemetry struct {
	Version          uint32
	Capacity         uint32
	WriteIdx         uint64
	DropCount        uint64
	TrapCount        uint64
	MTDEpoch         uint32
	DefenseFlags     uint32
	EntropyThreshold float64
}

// ReadTelemetry читает состояние контура защиты и счётчики ловушек через mmap.
func ReadTelemetry(shmPath string) (*RingTelemetry, error) {
	f, err := os.OpenFile(shmPath, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := syscall.Mmap(int(f.Fd()), 0, ZeroRingHeaderSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	defer syscall.Munmap(data)

	magic := binary.LittleEndian.Uint64(data[0:8])
	if magic != ZeroRingMagic {
		return nil, fmt.Errorf("invalid ZERORING magic: 0x%x", magic)
	}

	entX100 := binary.LittleEndian.Uint16(data[48:50])
	return &RingTelemetry{
		Version:          binary.LittleEndian.Uint32(data[8:12]),
		Capacity:         binary.LittleEndian.Uint32(data[12:16]),
		WriteIdx:         binary.LittleEndian.Uint64(data[16:24]),
		DropCount:        binary.LittleEndian.Uint64(data[24:32]),
		TrapCount:        uint64(binary.LittleEndian.Uint64(data[32:40])),
		MTDEpoch:         binary.LittleEndian.Uint32(data[40:44]),
		DefenseFlags:     binary.LittleEndian.Uint32(data[44:48]),
		EntropyThreshold: float64(entX100) / 100.0,
	}, nil
}

// UpdateDefensePolicy обновляет режим ловушек, MTD-эпоху и порог энтропии в реальном времени.
func UpdateDefensePolicy(shmPath string, mtdEpoch uint32, flags uint32, entropyThreshold float64) error {
	if entropyThreshold < 0 || entropyThreshold > 8.0 {
		return errors.New("shannon entropy threshold must be between 0.0 and 8.0")
	}
	f, err := os.OpenFile(shmPath, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := syscall.Mmap(int(f.Fd()), 0, ZeroRingHeaderSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return err
	}
	defer syscall.Munmap(data)

	binary.LittleEndian.PutUint32(data[40:44], mtdEpoch)
	binary.LittleEndian.PutUint32(data[44:48], flags)
	binary.LittleEndian.PutUint16(data[48:50], uint16(entropyThreshold*100))
	return nil
}
