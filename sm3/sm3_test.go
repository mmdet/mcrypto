package sm3

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestSm3ByBytes(t *testing.T) {
	//h := New()
	//h.Write([]byte("123"))
	//fmt.Printf("%x \n", h.Sum(nil))

	h := New()
	h.Write([]byte("3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a11111"))
	b := h.Sum(nil)

	fmt.Println(hex.EncodeToString(b))
}

func TestSm3ByFile(t *testing.T) {
	f, _ := os.Open("/Users/kisscat/Downloads/tkks_exam_client_setup_220816.exe")

	defer f.Close()

	h := New()

	buf := make([]byte, 1024*1024)
	//io.CopyBuffer(h, f, buf)

	for {
		bytesRead, err := f.Read(buf)
		if err != nil {
			if err != io.EOF {
				panic(err)
			}
			break
		}

		h.Write(buf[:bytesRead])
	}

	fmt.Printf("%x", h.Sum(nil))

}
