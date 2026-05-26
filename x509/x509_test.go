package x509

import (
	"fmt"
	"testing"
	"time"
)

func TestP7b(t *testing.T) {
	defer trackTime(time.Now())
	time.Sleep(5 * time.Second)
}
func trackTime(pre time.Time) time.Duration {
	els := time.Since(pre)
	fmt.Printf("耗时：%v \n", els)
	return els
}
