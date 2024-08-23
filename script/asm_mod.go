package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	x64, err := os.ReadFile("../dist/GleamRT_x64.bin")
	checkError(err)
	x86, err := os.ReadFile("../dist/GleamRT_x86.bin")
	checkError(err)
	err = os.WriteFile("../dist/GleamRT_x64.asm", dumpBytesHex(x64), 0600)
	checkError(err)
	err = os.WriteFile("../dist/GleamRT_x86.asm", dumpBytesHex(x86), 0600)
	checkError(err)
}

func dumpBytesHex(b []byte) []byte {
	n := len(b)
	builder := bytes.Buffer{}
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
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 16 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.Bytes()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
