package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

func main() {

}

// +---------+----------+-----------+----------+----------+
// |   key   | num args | args size | arg size | arg data |
// +---------+----------+-----------+----------+----------+
// | 32 byte |  uint32  |  uint32   |  uint32  |    var   |
// +---------+----------+-----------+----------+----------+

const OffsetRuntimeTail = 32 + 8 + (4 + 8) + (4 + 12)

const (
	cryptoKeySize  = 32
	offsetFirstArg = 32 + 4 + 4
)

func EncodeArguments(args [][]byte) ([]byte, error) {
	key := make([]byte, cryptoKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate crypto key")
	}
	// write crypto key
	buf := bytes.NewBuffer(make([]byte, 0, OffsetRuntimeTail))
	buf.Write(key)
	// write the number of arguments
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(args)))
	buf.Write(b)
	// calculate the total size of the arguments
	var totalSize int
	for i := 0; i < len(args); i++ {
		totalSize += len(args[i])
	}
	binary.LittleEndian.PutUint32(b, uint32(totalSize))
	buf.Write(b)
	// write arguments
	for i := 0; i < len(args); i++ {
		// write argument size
		binary.LittleEndian.PutUint32(b, uint32(len(args[i])))
		buf.Write(b)
		// write argument data
		buf.Write(args[i])
	}
	output := encryptArguments(buf.Bytes(), key)
	return output, nil
}

func encryptArguments(args, key []byte) []byte {
	data := args[offsetFirstArg:]
	var keyIdx = 0
	for i := 0; i < len(data); i++ {
		data[i] ^= key[keyIdx]
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
	}
	return args
}
