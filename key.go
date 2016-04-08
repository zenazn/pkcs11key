package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"github.com/miekg/pkcs11"
)

/*
// This is PKCS #11's CK_RSA_PKCS_PSS_PARAMS, with types expanded.
struct pss_params {
	unsigned long int hashAlg;
	unsigned long int mgf;
	unsigned long int sLen;
};
*/
import "C"

// Key is a handle to a PKCS #11 backed asymmetric key pair. Currently, only RSA
// and ECDSA keys are supported.
//
// Key implements crypto.Signer, and is safe for use from multiple goroutines.
type Key struct {
	slot            *Slot
	public, private pkcs11.ObjectHandle
	publicKey       crypto.PublicKey
}

// PublicKey returns the public half of the asymmetric key pair.
func (k *Key) Public() crypto.PublicKey {
	return k.publicKey
}

var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
	crypto.Hash(0):   {}, // Special case in the golang interface to indicate that data is signed directly
}

// Sign signs msg with a PKCS #11 backed private key.
//
// Sign supports both the PKCS #1 v1.5 and PSS signature schemes for RSA keys,
// and ECDSA signatures for ECDSA keys.
func (k *Key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	h, err := k.slot.alloc()
	if err != nil {
		return nil, err
	}
	defer k.slot.release(h)
	ctx := k.slot.module.ctx

	obj := obj{ctx, h, k.private}

	switch k.publicKey.(type) {
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			return signRSAPSS(obj, msg, pss)
		} else {
			// For PKCS #1 v1.5 RSA signatures, the input to the
			// actual signature function is an ASN.1 DER-encoded
			// structure. PKCS #11 has hash-specific mechanisms
			// (e.g. CKM_SHA256_RSA_PKCS) which know how to generate
			// that structure, but they all assume the data is
			// un-hashed, which is not the case with the
			// crypto.Signer interface, so we have to use the
			// generic CKA_RSA_PKCS mechanism, which just performs
			// the raw signature operation.
			//
			// This means we have to generate the ASN.1 structure
			// ourselves, which we can do by just having the correct
			// prefixes for all the hashes we might want to use.
			// Prefixes are taken from src/crypto/rsa/pkcs1v15.go.
			// No other signatures require this song and dance.
			prefix, ok := hashPrefixes[opts.HashFunc()]
			if !ok {
				return nil, fmt.Errorf("unsupported hash %v", opts.HashFunc())
			}
			msg = append(prefix, msg...)
			return signRSAPKCS1(obj, msg)
		}
	case *ecdsa.PublicKey:
		return signECDSA(obj, msg)
	default:
		panic(fmt.Sprintf("key was %T, not rsa or ecdsa", k.publicKey))
	}
}

func sign(obj obj, msg []byte, mech []*pkcs11.Mechanism) ([]byte, error) {
	if err := obj.ctx.SignInit(obj.h, mech, obj.o); err != nil {
		return nil, err
	}
	return obj.ctx.Sign(obj.h, msg)
}

func signRSAPSS(obj obj, msg []byte, opts *rsa.PSSOptions) ([]byte, error) {
	pss := new(C.struct_pss_params)
	switch opts.Hash {
	case crypto.SHA1:
		pss.hashAlg = pkcs11.CKM_SHA_1
		pss.mgf = 0x00000001 // CKG_MGF1_SHA1
	case crypto.SHA256:
		pss.hashAlg = pkcs11.CKM_SHA256
		pss.mgf = 0x00000002 // CKG_MGF1_SHA256
	case crypto.SHA384:
		pss.hashAlg = pkcs11.CKM_SHA384
		pss.mgf = 0x00000003 // CKG_MGF1_SHA384
	case crypto.SHA512:
		pss.hashAlg = pkcs11.CKM_SHA512
		pss.mgf = 0x00000004 // CKG_MGF1_SHA512
	default:
		return nil, fmt.Errorf("unsupported hash func: %v", opts.Hash)
	}
	pss.sLen = C.ulong(opts.SaltLength)
	pssBuf := C.GoBytes(unsafe.Pointer(pss), C.int(unsafe.Sizeof(*pss)))
	return sign(obj, msg, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pssBuf),
	})
}
func signRSAPKCS1(obj obj, msg []byte) ([]byte, error) {
	return sign(obj, msg, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
	})
}
func signECDSA(obj obj, msg []byte) ([]byte, error) {
	sig, err := sign(obj, msg, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil),
	})
	if err != nil {
		return nil, err
	}

	// Per PKCS #11 v2.20 Section 12.3.1, elliptic curve signatures are
	// composed of an even number of octets, where the first half is r and
	// the second half is s.
	if len(sig)%2 != 0 {
		return nil, fmt.Errorf("expected even number of octets: %v", len(sig))
	}
	ri := new(big.Int).SetBytes(sig[:len(sig)/2])
	si := new(big.Int).SetBytes(sig[len(sig)/2:])
	type ecSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecSig{ri, si})
}
