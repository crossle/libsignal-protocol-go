package main

import (
	groupRecord "github.com/trustasia-com/libsignal-protocol-go/groups/state/record"
	"github.com/trustasia-com/libsignal-protocol-go/keys/identity"
	"github.com/trustasia-com/libsignal-protocol-go/protocol"
	"github.com/trustasia-com/libsignal-protocol-go/serialize"
	"github.com/trustasia-com/libsignal-protocol-go/state/record"
)

func NewMixinSignalProtocolStore(serializer *serialize.Serializer) *MixinSignalProtocolStore {
	return &MixinSignalProtocolStore{
		IdentityKeyStore:  NewMixinIdentityKeyStore(),
		PreKeyStore:       NewMixinPreKeyStore(serializer),
		SessionStore:      NewMixinSessionStore(serializer),
		SignedPreKeyStore: NewMixinSignedPreKeyStore(serializer),
		SenderKeyStore:    NewMixinSenderKeyStore(serializer),
	}
}

type MixinSignalProtocolStore struct {
	IdentityKeyStore  *MixinIdentityKeyStore
	PreKeyStore       *MixinPreKeyStore
	SessionStore      *MixinSessionStore
	SignedPreKeyStore *MixinSignedPreKeyStore
	SenderKeyStore    *MixinSenderKeyStore
}

func (i *MixinSignalProtocolStore) GetIdentityKeyPair() *identity.KeyPair {
	return i.IdentityKeyStore.GetIdentityKeyPair()
}

func (i *MixinSignalProtocolStore) GetLocalRegistrationId() uint32 {
	return i.IdentityKeyStore.GetLocalRegistrationId()
}

func (i *MixinSignalProtocolStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	i.IdentityKeyStore.SaveIdentity(address, identityKey)
}

func (i *MixinSignalProtocolStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key) bool {
	return i.IdentityKeyStore.IsTrustedIdentity(address, identityKey)
}

func (i *MixinSignalProtocolStore) LoadPreKey(preKeyID uint32) *record.PreKey {
	return i.PreKeyStore.LoadPreKey(preKeyID)
}

func (i *MixinSignalProtocolStore) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	i.PreKeyStore.StorePreKey(preKeyID, preKeyRecord)
}

func (i *MixinSignalProtocolStore) ContainsPreKey(preKeyID uint32) bool {
	return i.PreKeyStore.ContainsPreKey(preKeyID)
}

func (i *MixinSignalProtocolStore) RemovePreKey(preKeyID uint32) {
	i.PreKeyStore.RemovePreKey(preKeyID)
}

func (i *MixinSignalProtocolStore) LoadSession(address *protocol.SignalAddress) *record.Session {
	return i.SessionStore.LoadSession(address)
}

func (i *MixinSignalProtocolStore) GetSubDeviceSessions(name string) []uint32 {
	return i.SessionStore.GetSubDeviceSessions(name)
}

func (i *MixinSignalProtocolStore) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) {
	i.SessionStore.StoreSession(remoteAddress, record)
}

func (i *MixinSignalProtocolStore) ContainsSession(remoteAddress *protocol.SignalAddress) bool {
	return i.SessionStore.ContainsSession(remoteAddress)
}

func (i *MixinSignalProtocolStore) DeleteSession(remoteAddress *protocol.SignalAddress) {
	i.SessionStore.DeleteSession(remoteAddress)
}

func (i *MixinSignalProtocolStore) DeleteAllSessions() {
	// i.sessions = make(map[*protocol.SignalAddress]*record.Session)
	i.SessionStore.DeleteAllSessions()
}

func (i *MixinSignalProtocolStore) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	return i.SignedPreKeyStore.LoadSignedPreKey(signedPreKeyID)
}

func (i *MixinSignalProtocolStore) LoadSignedPreKeys() []*record.SignedPreKey {
	return i.SignedPreKeyStore.LoadSignedPreKeys()
}

func (i *MixinSignalProtocolStore) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) {
	i.SignedPreKeyStore.StoreSignedPreKey(signedPreKeyID, record)
}

func (i *MixinSignalProtocolStore) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	return i.SignedPreKeyStore.ContainsSignedPreKey(signedPreKeyID)
}

func (i *MixinSignalProtocolStore) RemoveSignedPreKey(signedPreKeyID uint32) {
	i.SignedPreKeyStore.RemoveSignedPreKey(signedPreKeyID)
}

func (i *MixinSignalProtocolStore) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) {
	i.SenderKeyStore.StoreSenderKey(senderKeyName, keyRecord)
}

func (i *MixinSignalProtocolStore) LoadSenderKey(senderKeyName *protocol.SenderKeyName) *groupRecord.SenderKey {
	return i.SenderKeyStore.LoadSenderKey(senderKeyName)
}
