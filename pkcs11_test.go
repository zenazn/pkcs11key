package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

var msg = []byte("hello world")
var sha = sha256.Sum256(msg)

func TestRSA(t *testing.T) {
	hsm, err := NewSoftHSM()
	if err != nil {
		if err == errNoSoftHSM {
			t.Skip(err)
		} else {
			t.Fatal("initializing hsm:", err)
		}
	}
	defer hsm.Close()

	slot, err := NewSlot(hsm.Module, 0, PIN)
	if err != nil {
		t.Fatal("NewSlot:", err)
	}
	defer slot.Close()

	key, err := slot.Key(RSAKeyID)
	if err != nil {
		t.Fatal("Key:", err)
	}

	pub := key.Public().(*rsa.PublicKey)

	sig, err := key.Sign(nil, sha[:], crypto.SHA256)
	if err != nil {
		t.Error("Signing with PKCS1v15:", err)
	} else if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sha[:], sig); err != nil {
		t.Error("PKCS1v15 verification:", err)
	}

	// Unfortunately SoftHSM does not support PSS signatures

	/*
		sig, err = s.Sign(nil, sha[:], &rsa.PSSOptions{Hash: crypto.SHA256})
		if err != nil {
			t.Error("Signing with PSS:", err)
		} else if err := rsa.VerifyPSS(pub, crypto.SHA256, shabuf, sig, nil); err != nil {
			t.Error("PSS verification:", err)
		}
	*/
}

func TestECDSA(t *testing.T) {
	hsm, err := NewSoftHSM()
	if err != nil {
		if err == errNoSoftHSM {
			t.Skip(err)
		} else {
			t.Fatal("initializing hsm:", err)
		}
	}
	defer hsm.Close()

	slot, err := NewSlot(hsm.Module, 0, PIN)
	if err != nil {
		t.Fatal("NewSlot:", err)
	}
	defer slot.Close()

	key, err := slot.Key(ECDSAKeyID)
	if err != nil {
		t.Fatal("Key:", err)
	}

	pub := key.Public().(*ecdsa.PublicKey)

	sig, err := key.Sign(nil, sha[:], crypto.SHA256)
	if err != nil {
		t.Error("Signing:", err)
	}

	var asnSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &asnSig); err != nil {
		t.Fatal("bad format:", err)
	}
	if !ecdsa.Verify(pub, sha[:], asnSig.R, asnSig.S) {
		t.Error("Error verifying")
	}
}
