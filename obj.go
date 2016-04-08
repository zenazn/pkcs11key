package pkcs11key

import "github.com/miekg/pkcs11"

type obj struct {
	ctx *pkcs11.Ctx
	h   pkcs11.SessionHandle
	o   pkcs11.ObjectHandle
}
