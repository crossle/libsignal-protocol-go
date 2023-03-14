package store

import (
	"github.com/trustasia-com/libsignal-protocol-go/groups/state/store"
)

// SignalProtocol store is an interface that implements the
// methods for all stores needed in the Signal Protocol.
type SignalProtocol interface {
	IdentityKey
	PreKey
	Session
	SignedPreKey
	store.SenderKey
}
