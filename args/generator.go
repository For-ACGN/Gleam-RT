package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	args := [][]byte{
		{0x78, 0x56, 0x34, 0x12},
		[]byte("aaaabbbbccc\x00"),
		{},
	}
	output, err := EncodeArgStub(args)
	checkError(err)

	fmt.Println(dumpBytesHex(output))

	args, err = DecodeArgStub(output)
	checkError(err)
	fmt.Println(args)
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

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// +---------+----------+----------+-----------+----------+----------+
// |   key   | checksum | num args | args size | arg size | arg data |
// +---------+----------+----------+-----------+----------+----------+
// | 32 byte |  uint32  |  uint32  |  uint32   |  uint32  |   var    |
// +---------+----------+----------+-----------+----------+----------+

const (
	cryptoKeySize  = 32
	offsetChecksum = 32
	offsetNumArgs  = 32 + 4
	offsetFirstArg = 32 + 4 + 4 + 4
)

// EncodeArgStub is used to encode and encrypt arguments for runtime
func EncodeArgStub(args [][]byte) ([]byte, error) {
	key := make([]byte, cryptoKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate crypto key")
	}
	// write crypto key
	buffer := bytes.NewBuffer(make([]byte, 0, offsetFirstArg))
	buffer.Write(key)
	// reserve space for checksum
	buffer.Write(make([]byte, 4))
	// write the number of arguments
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(args)))
	buffer.Write(buf)
	// calculate the total size of the arguments
	var totalSize int
	for i := 0; i < len(args); i++ {
		totalSize += 4 + len(args[i])
	}
	binary.LittleEndian.PutUint32(buf, uint32(totalSize))
	buffer.Write(buf)
	// write arguments
	for i := 0; i < len(args); i++ {
		// write argument size
		binary.LittleEndian.PutUint32(buf, uint32(len(args[i])))
		buffer.Write(buf)
		// write argument data
		buffer.Write(args[i])
	}
	output := buffer.Bytes()
	// calculate checksum
	var checksum uint32
	for _, b := range output[offsetFirstArg:] {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	binary.LittleEndian.PutUint32(output[offsetChecksum:], checksum)
	encryptArgStub(output)
	return output, nil
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

// DecodeArgStub is used to decode and decrypt arguments from raw stub.
func DecodeArgStub(stub []byte) ([][]byte, error) {
	if len(stub) < offsetFirstArg {
		return nil, errors.New("stub is too short")
	}
	numArgs := binary.LittleEndian.Uint32(stub[offsetNumArgs:])
	if numArgs == 0 {
		return nil, nil
	}
	decryptArgStub(stub)
	// calculate checksum
	var checksum uint32
	for _, b := range stub[offsetFirstArg:] {
		checksum += checksum << 1
		checksum += uint32(b)
	}
	expected := binary.LittleEndian.Uint32(stub[offsetChecksum:])
	if checksum != expected {
		return nil, errors.New("invalid checksum")
	}
	// decode arguments
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
