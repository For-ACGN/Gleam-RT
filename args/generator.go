package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func main() {
	args := [][]byte{
		{0x78, 0x56, 0x34, 0x12},
		[]byte("aaaabbbbccc\x00"),
	}
	output, err := EncodeArgStub(args)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(dumpBytesHex(output))

	fmt.Println(DecodeArgStub(output))
}

func dumpBytesHex(b []byte) string {
	n := len(b)
	builder := strings.Builder{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		counter++
		if counter != 4 {
			builder.WriteString(", ")
			continue
		}
		builder.WriteString("\r\n")
		counter = 0
	}
	return builder.String()
}

// +---------+----------+-----------+----------+----------+
// |   key   | num args | args size | arg size | arg data |
// +---------+----------+-----------+----------+----------+
// | 32 byte |  uint32  |  uint32   |  uint32  |   var    |
// +---------+----------+-----------+----------+----------+

const (
	cryptoKeySize  = 32
	offsetFirstArg = 32 + 4 + 4
)

// EncodeArgStub is used to encode and encrypt arguments for runtime
func EncodeArgStub(args [][]byte) ([]byte, error) {
	key := make([]byte, cryptoKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate crypto key")
	}
	// write crypto key
	buf := bytes.NewBuffer(make([]byte, 0, offsetFirstArg))
	buf.Write(key)
	// write the number of arguments
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(args)))
	buf.Write(b)
	// calculate the total size of the arguments
	var totalSize int
	for i := 0; i < len(args); i++ {
		totalSize += 4 + len(args[i])
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
	output := buf.Bytes()
	encryptArgStub(output)
	return output, nil
}

// DecodeArgStub is used to decode and decrypt arguments from raw stub.
func DecodeArgStub(stub []byte) ([][]byte, error) {
	if len(stub) < offsetFirstArg {
		return nil, errors.New("stub is too short")
	}
	numArgs := binary.LittleEndian.Uint32(stub[cryptoKeySize:])
	if numArgs == 0 {
		return nil, nil
	}
	decryptArgStub(stub)
	args := make([][]byte, 0, numArgs)
	offset := offsetFirstArg
	for i := 0; i < int(numArgs); i++ {
		l := binary.LittleEndian.Uint32(stub[offset:])
		arg := make([]byte, l)
		copy(arg, stub[offset+4:offset+4+int(l)])
		args = append(args, arg)
		offset += 4 + int(l)
	}
	return args, nil
}

func encryptArgStub(stub []byte) {
	key := stub[:cryptoKeySize]
	data := stub[offsetFirstArg:]
	last := byte(0xFF)
	var keyIdx = 0
	for i := 0; i < len(data); i++ {
		b := data[i] ^ last
		b ^= key[keyIdx]
		last = data[i]
		data[i] = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
	}
}

func decryptArgStub(stub []byte) {
	key := stub[:cryptoKeySize]
	data := stub[offsetFirstArg:]
	last := byte(0xFF)
	var keyIdx = 0
	for i := 0; i < len(data); i++ {
		b := data[i] ^ last
		b ^= key[keyIdx]
		data[i] = b
		last = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
	}
}
