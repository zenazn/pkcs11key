package pkcs11key

import (
	"sync"

	"github.com/miekg/pkcs11"
)

/*
Unfortunately, PKCS #11 requires us to keep a lot of global state:

- dlopen (actually lt_dlopen) only opens any given dynamic library once;
  subsequent loads return the same object. Therefore calls to C_Initialize and
  C_Finalize affect global state in the dynamic library, and we must refcount
  calls to them to prevent one logical copy of a module from destroying another
  logical copy's state.

- Login state to a slot is global across all sessions (past and future) to that
  slot. Therefore, we yet again need to refcount calls to C_Login and C_Logout.
*/

type pkcs11Module struct {
	name     string
	ctx      *pkcs11.Ctx
	refcount int

	slots map[uint]*pkcs11Slot
}

type pkcs11Slot struct {
	module   *pkcs11Module
	id       uint
	pin      string
	refcount int

	loginSession pkcs11.SessionHandle
}

var mu sync.Mutex
var modules = map[string]*pkcs11Module{}

// Must be called with mu held
func refModule(name string) (*pkcs11Module, error) {
	module := modules[name]
	if module == nil {
		module = &pkcs11Module{
			name:  name,
			ctx:   pkcs11.New(name),
			slots: make(map[uint]*pkcs11Slot),
		}
		if err := module.ctx.Initialize(); err != nil {
			module.ctx.Destroy()
			return nil, err
		}

		// The Yubikey Neo implementation of PKCS #11 does not seem to
		// allow the creation of sessions until you call GetSlotList at
		// least once.  Doing so is harmless, so as a workaround let's
		// do that for now.
		if _, err := module.ctx.GetSlotList(true); err != nil {
			module.ctx.Destroy()
			return nil, err
		}

		modules[name] = module
	}
	module.refcount++
	return module, nil
}

// Must be called with mu held
func derefModule(name string) {
	modules[name].refcount--
	if modules[name].refcount == 0 {
		modules[name].ctx.Finalize()
		modules[name].ctx.Destroy()
		delete(modules, name)
	}
}

// Must be called with mu held
func refSlot(module *pkcs11Module, id uint, pin string) (*pkcs11Slot, error) {
	slot := module.slots[id]
	if slot == nil {
		slot = &pkcs11Slot{
			module: module,
			id:     id,
			pin:    pin,
		}
		loginSession, err := module.ctx.OpenSession(id, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return nil, err
		}
		slot.loginSession = loginSession
		err = module.ctx.Login(loginSession, pkcs11.CKU_USER, pin)
		if err != nil {
			module.ctx.CloseSession(loginSession)
			return nil, err
		}
		module.slots[id] = slot
	}
	slot.refcount++

	return slot, nil
}

// Must be called with mu held
func derefSlot(module *pkcs11Module, id uint) {
	module.slots[id].refcount--
	if module.slots[id].refcount == 0 {
		module.ctx.Logout(module.slots[id].loginSession)
		module.ctx.CloseSession(module.slots[id].loginSession)
		delete(module.slots, id)
	}
}
