package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// Slot is a handle to a slot on a PKCS #11 module. Slots are safe for use from
// multiple goroutines.
type Slot struct {
	*pkcs11Slot
}

// NewSlot returns a new Slot handle from the given PKCS #11 module, the slot
// ID, and the PIN necessary to unlock that slot. Some slots do not require
// PINs, perhaps because PIN entry is done out-of-band (using a dedicated PIN
// entry device, for instance). In this case, pass the empty string.
func NewSlot(module string, slotID uint, pin string) (s *Slot, err error) {
	var mod *pkcs11Module
	var slot *pkcs11Slot
	mu.Lock()
	defer func() {
		if err != nil && slot != nil {
			derefSlot(mod, slotID)
		}
		if err != nil && mod != nil {
			derefModule(mod.name)
		}
		mu.Unlock()
	}()

	mod, err = refModule(module)
	if err != nil {
		return
	}
	slot, err = refSlot(mod, slotID, pin)
	if err != nil {
		return
	}
	return &Slot{slot}, nil
}

// Close deallocates resources used by the given slot. It must be called on
// every Slot object.
func (s *Slot) Close() {
	derefSlot(s.module, s.id)
	derefModule(s.module.name)
}

// TODO(carl): session pooling
func (s *Slot) alloc() (pkcs11.SessionHandle, error) {
	return s.module.ctx.OpenSession(s.id, pkcs11.CKF_SERIAL_SESSION)
}
func (s *Slot) release(h pkcs11.SessionHandle) error {
	return s.module.ctx.CloseSession(h)
}

// Key returns a Key backed by the key pair with the given hex-encoded ID.
func (s *Slot) Key(id string) (*Key, error) {
	rawID, err := hex.DecodeString(id)
	if err != nil {
		return nil, err
	}

	return s.findKey([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, rawID),
	})
}

func (s *Slot) findKey(search []*pkcs11.Attribute) (*Key, error) {
	h, err := s.alloc()
	if err != nil {
		return nil, err
	}
	defer s.release(h)

	if err := s.module.ctx.FindObjectsInit(h, search); err != nil {
		return nil, err
	}
	objs, more, err := s.module.ctx.FindObjects(h, 2)
	if err != nil {
		return nil, err
	}
	if len(objs) != 2 {
		return nil, fmt.Errorf("pkcs11: expected two keys, got %v", len(objs))
	} else if more {
		return nil, fmt.Errorf("pkcs11: expected two keys, got more than two")
	}
	if err := s.module.ctx.FindObjectsFinal(h); err != nil {
		return nil, err
	}

	c0, t0, err := describeKey(obj{s.module.ctx, h, objs[0]})
	if err != nil {
		return nil, err
	}
	c1, t1, err := describeKey(obj{s.module.ctx, h, objs[1]})
	if err != nil {
		return nil, err
	}
	var pub, priv pkcs11.ObjectHandle
	if c0 == "public" && c1 == "private" {
		pub = objs[0]
		priv = objs[1]
	} else if c0 == "private" && c1 == "public" {
		pub = objs[1]
		priv = objs[0]
	} else {
		return nil, fmt.Errorf("pkcs11: got keys of class %s and %s", c0, c1)
	}
	if t0 != t1 {
		return nil, fmt.Errorf("pkcs11: got keys of type %s and %s", t0, t1)
	}
	pubkey, err := publicKey(obj{s.module.ctx, h, pub}, t0)
	if err != nil {
		return nil, err
	}
	return &Key{
		slot:      s,
		public:    pub,
		private:   priv,
		publicKey: pubkey,
	}, nil
}

func describeKey(obj obj) (c, t string, err error) {
	attrs, err := obj.ctx.GetAttributeValue(obj.h, obj.o, []*pkcs11.Attribute{
		&pkcs11.Attribute{Type: pkcs11.CKA_CLASS},
		&pkcs11.Attribute{Type: pkcs11.CKA_KEY_TYPE},
	})
	if err != nil {
		return
	}

	switch btoi(attrs[0].Value) {
	case pkcs11.CKO_PUBLIC_KEY:
		c = "public"
	case pkcs11.CKO_PRIVATE_KEY:
		c = "private"
	default:
		err = fmt.Errorf("pkcs11: unknown key class %x", btoi(attrs[0].Value))
	}

	switch btoi(attrs[1].Value) {
	case pkcs11.CKK_RSA:
		t = "rsa"
	case pkcs11.CKK_ECDSA:
		t = "ecdsa"
	case pkcs11.CKK_DSA:
		err = fmt.Errorf("pkcs11: DSA keys are not supported")
	default:
		err = fmt.Errorf("pkcs11: unknown key type %x", btoi(attrs[1].Value))
	}
	return
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func publicKey(obj obj, t string) (crypto.PublicKey, error) {
	switch t {
	case "rsa":
		attrs, err := obj.ctx.GetAttributeValue(obj.h, obj.o, []*pkcs11.Attribute{
			&pkcs11.Attribute{Type: pkcs11.CKA_MODULUS},
			&pkcs11.Attribute{Type: pkcs11.CKA_PUBLIC_EXPONENT},
		})
		if err != nil {
			return nil, err
		}
		modulus := new(big.Int).SetBytes(attrs[0].Value)
		exponent := new(big.Int).SetBytes(attrs[1].Value)
		return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
	case "ecdsa":
		attrs, err := obj.ctx.GetAttributeValue(obj.h, obj.o, []*pkcs11.Attribute{
			&pkcs11.Attribute{Type: pkcs11.CKA_EC_PARAMS},
			&pkcs11.Attribute{Type: pkcs11.CKA_EC_POINT},
		})
		if err != nil {
			return nil, err
		}
		// We only handle named curves, which are specified by a
		// well-known OID.
		var curveOID asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(attrs[0].Value, &curveOID); err != nil {
			return nil, fmt.Errorf("bad curve (probably non-named curve): %v", err)
		}
		var curve elliptic.Curve
		switch {
		case curveOID.Equal(oidNamedCurveP224):
			curve = elliptic.P224()
		case curveOID.Equal(oidNamedCurveP256):
			curve = elliptic.P256()
		case curveOID.Equal(oidNamedCurveP384):
			curve = elliptic.P384()
		case curveOID.Equal(oidNamedCurveP521):
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unknown named curve: %v", curveOID)
		}

		var ecbuf []byte
		_, err = asn1.Unmarshal(attrs[1].Value, &ecbuf)
		if err != nil {
			return nil, fmt.Errorf("bad point: %v", err)
		}

		x, y := elliptic.Unmarshal(curve, ecbuf)
		if x == nil {
			return nil, fmt.Errorf("bad public key")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		panic("unknown key type")
	}
}
