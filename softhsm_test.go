package pkcs11

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
)

const PIN = "1234"

// PKCS#8-encoded 2048-bit RSA private key, generated using `openssl genrsa 2048
// | openssl pkcs8 -topk8 -nocrypt`, so encoded because Go can't generate pkcs8
const RSAKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDOsqCGyHmaS5xp
iuzcWQaxrRQrB51dXJItQTl59f8kcCyBMOod18nJtIMrTpjG2bBoSVUw/Gpmu2e+
aasom2YIe5AZKSJf56lI/ZYo8HXAG1ARZb0FlmpbDcH6DPRM/0gU/cJGN+hWTUU6
sffOKEUTIbS/gjUCQAIT4oOxNEmzPvdDat3Z1+jWLsC2kx4gL2p8AMOa6NLNlNgQ
6Zc2ulAmquv/RcyEq7300IAv+ysMGBNAjJVSCEptcGUaewrRrfYry0kkw7NNCq3Y
e9mC2gr0MxB9yR/VPOdWAZrNBh5FSesQsQvFa2C+rETjcscrKyaRZbMG9pFy6cDM
4Ll7lP3ZAgMBAAECggEBAILC1nLuGJ/X/Zd3X+j2GRoGGKAwLQmHKqKehLH3QfXX
URBZ1YITpYCJRgH7swL5bHRNECvxQ47COBtp1fHWfXIYWUzRjQGHGL0oT/qORK/H
l5up9S63vYjk5zY9Q8ACL6O39VNewwj10ToUpGQzbZ9wz1voD4jg3W+e+Rj9rzJJ
G+tILAPOdUt86FiGziFTZHSuWSq8C8bfqRYZIqK9ohMABdC+IGTKSy7SIkp/Q3TZ
xHGTx12vDYetClWr4q6nPAj0rLshV81FOUc0Pj9UWS+jL6cgZkwX2qflbzInN1CC
TJ4NKEyVmd6EJ3NeHKVTzvxGzVrhE7wCx7juiWiFmkECgYEA8BFLQY3gUPq7Qg6X
3QeeoNEMAMp1bNe5SlVLChsLvOIDZqIQsbsdYFf4xKiZnYKcJO9Nrv+cccPe3BJl
v0QVemdZKGauRnodQFHJ21v09xQld0DjI3SgCevjU0nM3CaEkKPa+csRwKsqgsAK
Yx1QOHmf4YJmYZY/0a7OIevgrZ0CgYEA3Gpi2B3dTqOLel/d+Fupeas8M82grgmL
unN2FyxtBTkhxgUiB8ay/mSe60q2QbZBQ5SlhCLpPtkSkpK6FNSK6EqajIcqhjKn
C8qhqHm3tAuLfcJFHZ5YgdWBvu6yWJKldeNBLFIK8gZtyjFm9U86tXu9wbNNb3qF
aBevu/Kzum0CgYEA1G/ZUpdD6yUVVC0pwdQeUVzr7D88jiaPtvGnR7gLOQgfzlCX
yU81fa4bW5t+5F1R43VIHxXe0OVtbv1wwEJ1Zy3RPekvSvqArAw0PkMvkP1o8hCf
bx6jCGSPc4KZIC+Nm5kEC4vhl8dgBPf/uRmVhYRLMPl9s9mLe/fePTJIThkCgYEA
w6AQdmubHc59XnFzmpgQBJJ77iZUs+J5B1SuvMaLRBV+6jdoCqrJ9orrmT1IIW5W
4lotxOcPSN50Y26ihRZW6vA71vmoPk76f7aqX9MXvk540Xb4zN7bAvCyJPnJhF8z
RzwZffKbEE+wZcIO9S4Kl0RqGF7BHW4KtWZAbHluFskCgYBKOipgwTYVgLOGEN5m
RkaSoXfvJfsbQGuDE4vWfE7DWIAmqbtHs8oWVfBLUG9kLcfoM2j1rnVQjwemcbVN
7XEII3KgFhWU0XhNid7aHpdji5pQ/qeRbzGIqY3BHja4fDrFpKBhyfD3gHlQiuje
m7AVsoAPq1e88wkJU7bJ2ptCVg==
-----END PRIVATE KEY-----`

const RSAKeyID = "01"

// Likewise for a P-256 key, generated using `openssl ecparam -name prime256v1
// -genkey | openssl pkcs8 -topk8 -nocrypt`.
const ECDSAKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgw93FFBHTBMFEhI3t
vWXkT0Vc8KNTGAaS91qp+kQiPuChRANCAATK7HX8PvLTn92DUAblfsIGFXmbJoQZ
VAacwYDYK8ipGO8kUGTRpLojrZ2yK4kPZa4WtGVZp9PU/Q807O/JfJ8v
-----END PRIVATE KEY-----`

const ECDSAKeyID = "02"

// We use SoftHSM 2.0.0 as a testing PKCS11 interface.
type SoftHSM struct {
	Dir    string
	Module string
}

const softhsmModule = "./softhsm/lib/softhsm/libsofthsm2.so"
const softhsmUtil = "./softhsm/bin/softhsm2-util"

var errNoSoftHSM = fmt.Errorf("SoftHSM is not configured. Please run pkcs11/install-deps if you want to test against SoftHSM")

func NewSoftHSM() (*SoftHSM, error) {
	if _, err := os.Stat(softhsmModule); err != nil {
		return nil, errNoSoftHSM
	}

	dir, err := ioutil.TempDir("", "rsa")
	if err != nil {
		return nil, err
	}

	confPath := path.Join(dir, "softhsm2.conf")
	conf := fmt.Sprintf("directories.tokendir = %s", dir)
	if err := ioutil.WriteFile(confPath, []byte(conf), 0644); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	// Unfortunately this means we can't run tests in parallel, because the
	// two copies of SoftHSM would share a database.
	os.Setenv("SOFTHSM2_CONF", confPath)

	cmd := exec.Command(softhsmUtil, "--init-token", "--slot", "0", "--label", "test", "--so-pin", PIN, "--pin", PIN)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("init-token: %v", err)
	}
	cmd = exec.Command(softhsmUtil, "--import", "/dev/fd/0", "--slot", "0", "--label", "RSA", "--id", RSAKeyID, "--pin", PIN)
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(RSAKey)
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("import rsa: %v", err)
	}
	cmd = exec.Command(softhsmUtil, "--import", "/dev/fd/0", "--slot", "0", "--label", "RSA", "--id", ECDSAKeyID, "--pin", PIN)
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(ECDSAKey)
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("import ecdsa: %v", err)
	}

	return &SoftHSM{
		Dir:    dir,
		Module: softhsmModule,
	}, nil
}

func (s *SoftHSM) Close() error {
	return os.RemoveAll(s.Dir)
}
