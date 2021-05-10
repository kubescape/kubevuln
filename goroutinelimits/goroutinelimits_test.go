package goroutinelimits

import (
	"fmt"
	"testing"
	"time"
)

func TestAbs(t *testing.T) {
	goroutineLimit, _ := CreateCoroutineGuardian(MAX_VULN_SCAN_ROUTINS)

	for i := 0; i < 30; i++ {
		goroutineLimit.Wait()
		go func(n int) {
			worker(n)
			goroutineLimit.Release()
		}(i)

		if len(goroutineLimit.Guard) > MAX_VULN_SCAN_ROUTINS {
			t.Errorf("queue size bound by %v", MAX_VULN_SCAN_ROUTINS)
		}
	}
	time.Sleep(20 * time.Second)

}
func worker(i int) {
	fmt.Println("doing work on", i)
}
