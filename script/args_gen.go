package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	
	"github.com/RSSU-Shellcode/RT-Argument"
)

func main() {
	args := [][]byte{
		{0x78, 0x56, 0x34, 0x12},
		[]byte("aaaabbbbccc\x00"),
		make([]byte, 0),
	}
	stub, err := argument.Encode(args)
	checkError(err)
	
	fmt.Println(dumpBytesHex(stub))
	
	args, err = argument.Decode(stub)
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
