package goroutinelimits

const (
	MAX_VULN_SCAN_ROUTINS = 10
)

/*
limit the number of goroutines we run to a specific number(e.g 10)
see this idiom: https://play.golang.org/p/seEp-erXjG6 ,


*/
type CoroutineGuardian struct {
	Guard chan struct{}
}

func CreateCoroutineGuardian(maximumRoutines int) (*CoroutineGuardian, error) {

	return &CoroutineGuardian{Guard: make(chan struct{}, maximumRoutines)}, nil

}

func (guardi *CoroutineGuardian) Wait() {
	guardi.Guard <- struct{}{}

}

func (guardi *CoroutineGuardian) Release() {
	<-guardi.Guard
}
