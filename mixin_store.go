package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"syscall/js"

	"github.com/trustasia-com/libsignal-protocol-go/ecc"
	groupRecord "github.com/trustasia-com/libsignal-protocol-go/groups/state/record"
	"github.com/trustasia-com/libsignal-protocol-go/keys/identity"
	"github.com/trustasia-com/libsignal-protocol-go/logger"
	"github.com/trustasia-com/libsignal-protocol-go/protocol"
	"github.com/trustasia-com/libsignal-protocol-go/serialize"
	"github.com/trustasia-com/libsignal-protocol-go/state/record"
	"github.com/trustasia-com/libsignal-protocol-go/util/bytehelper"
)

// IdentityKeyStore
func NewMixinIdentityKeyStore() *MixinIdentityKeyStore {
	return &MixinIdentityKeyStore{}
}

type MixinIdentityKeyStore struct {
}

func (i *MixinIdentityKeyStore) GetIdentityKeyPair() *identity.KeyPair {
	result := js.Global().Get("signalDao").Call("getIdentityKeyPair")
	public, _ := base64.StdEncoding.DecodeString(result.Get("public_key").String())
	private, _ := base64.StdEncoding.DecodeString(result.Get("private_key").String())

	privateKey := ecc.NewDjbECPrivateKey(bytehelper.SliceToArray(private))

	publicKeyable, _ := ecc.DecodePoint(public, 0)
	publicKey := identity.NewKey(publicKeyable)
	identityKeyPair := identity.NewKeyPair(publicKey, privateKey)
	return identityKeyPair
}

func (i *MixinIdentityKeyStore) GetLocalRegistrationId() uint32 {
	result := js.Global().Get("signalDao").Call("getIdentityKeyPair")
	return uint32(result.Get("registration_id").Int())
}

func (i *MixinIdentityKeyStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	pub := base64.StdEncoding.EncodeToString(identityKey.Serialize())
	js.Global().Get("signalDao").Call("saveIdentityKey", address.Name(), pub)
}

func (i *MixinIdentityKeyStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key) bool {
	result := js.Global().Get("signalDao").Call("getIdentityKey", address.Name())
	if result.IsUndefined() {
		return true
	}
	public, _ := base64.StdEncoding.DecodeString(result.Get("public_key").String())
	if hex.EncodeToString(public) == identityKey.Fingerprint() {
		return true
	}
	// TODO
	return true
}

// PreKeyStore
func NewMixinPreKeyStore(serializer *serialize.Serializer) *MixinPreKeyStore {
	return &MixinPreKeyStore{
		serializer: serializer,
	}
}

type MixinPreKeyStore struct {
	serializer *serialize.Serializer
}

func (i *MixinPreKeyStore) LoadPreKey(preKeyID uint32) *record.PreKey {
	result := js.Global().Get("signalDao").Call("getPreKey", preKeyID)
	if result.IsUndefined() {
		return nil
	}
	recordBytes := []byte(result.Get("record").String())
	preKey, err := record.NewPreKeyFromBytes(recordBytes, i.serializer.PreKeyRecord)
	if err != nil {
		return nil
	}
	return preKey
}

func (i *MixinPreKeyStore) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	record := hex.EncodeToString(preKeyRecord.Serialize())
	js.Global().Get("signalDao").Call("savePreKey", preKeyID, record)
}

func (i *MixinPreKeyStore) ContainsPreKey(preKeyID uint32) bool {
	result := js.Global().Get("signalDao").Call("getPreKey", preKeyID)
	if result.IsUndefined() {
		return false
	}
	return true
}

func (i *MixinPreKeyStore) RemovePreKey(preKeyID uint32) {
	js.Global().Get("signalDao").Call("deletePreKey", preKeyID)
}

// SessionStore
func NewMixinSessionStore(serializer *serialize.Serializer) *MixinSessionStore {
	return &MixinSessionStore{
		serializer: serializer,
	}
}

type MixinSessionStore struct {
	serializer *serialize.Serializer
}

func (i *MixinSessionStore) LoadSession(address *protocol.SignalAddress) *record.Session {
	result := js.Global().Get("signalDao").Call("getSession", address.Name(), address.DeviceID())
	if result.IsUndefined() {
		sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
		return sessionRecord
	}
	recordResult := result.Get("record")
	serialized, err := hex.DecodeString(recordResult.String())
	if err != nil {
		fmt.Println(err)
	}
	sessionRecord, err := record.NewSessionFromBytes(serialized, i.serializer.Session, i.serializer.State)
	if err != nil {
		fmt.Println(err)
	}
	return sessionRecord
}

func (i *MixinSessionStore) GetSubDeviceSessions(name string) []uint32 {
	var deviceIDs []uint32

	return deviceIDs
}

func (i *MixinSessionStore) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) {
	rec := hex.EncodeToString(record.Serialize())
	js.Global().Get("signalDao").Call("saveSession", remoteAddress.Name(), remoteAddress.DeviceID(), rec)
}

func (i *MixinSessionStore) ContainsSession(remoteAddress *protocol.SignalAddress) bool {
	result := js.Global().Get("signalDao").Call("getSession", remoteAddress.Name(), remoteAddress.DeviceID())
	if result.IsUndefined() {
		return false
	}
	return true
}

func (i *MixinSessionStore) DeleteSession(remoteAddress *protocol.SignalAddress) {
	js.Global().Get("signalDao").Call("deleteSession", remoteAddress.Name(), remoteAddress.DeviceID())
}

func (i *MixinSessionStore) DeleteAllSessions() {
	// i.sessions = make(map[*protocol.SignalAddress]*record.Session)
}

// SignedPreKeyStore
func NewMixinSignedPreKeyStore(serializer *serialize.Serializer) *MixinSignedPreKeyStore {
	return &MixinSignedPreKeyStore{
		serializer: serializer,
	}
}

type MixinSignedPreKeyStore struct {
	serializer *serialize.Serializer
}

func (i *MixinSignedPreKeyStore) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	result := js.Global().Get("signalDao").Call("getSignedPreKey", signedPreKeyID)
	logger.Debug("Load Signed PreKey result: ", result)
	if result.IsUndefined() {
		return nil
	}
	recordResult := result.Get("record")
	serialized := []byte(recordResult.String())
	signedPreKey, err := record.NewSignedPreKeyFromBytes(serialized, i.serializer.SignedPreKeyRecord)
	if err != nil {
		return nil
	}
	return signedPreKey
}

func (i *MixinSignedPreKeyStore) LoadSignedPreKeys() []*record.SignedPreKey {
	result := js.Global().Get("signalDao").Call("getAllSignedPreKeys")
	if result.IsUndefined() {
		return nil
	}

	var preKeys []*record.SignedPreKey

	// for _, record := range i.store {
	// 	preKeys = append(preKeys, record)
	// }

	return preKeys
}

func (i *MixinSignedPreKeyStore) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) {
	recordStr := hex.EncodeToString(record.Serialize())
	js.Global().Get("signalDao").Call("saveSignedPreKey", signedPreKeyID, recordStr)
}

func (i *MixinSignedPreKeyStore) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	result := js.Global().Get("signalDao").Call("getSignedPreKey", signedPreKeyID)
	if result.IsUndefined() {
		return false
	}
	return true
}

func (i *MixinSignedPreKeyStore) RemoveSignedPreKey(signedPreKeyID uint32) {
	js.Global().Get("signalDao").Call("deleteSignedPreKey", signedPreKeyID)
}

func NewMixinSenderKeyStore(serializer *serialize.Serializer) *MixinSenderKeyStore {
	return &MixinSenderKeyStore{
		serializer:      serializer.SenderKeyRecord,
		stateSerializer: serializer.SenderKeyState,
	}
}

type MixinSenderKeyStore struct {
	serializer      groupRecord.SenderKeySerializer
	stateSerializer groupRecord.SenderKeyStateSerializer
}

func (i *MixinSenderKeyStore) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) {
	recordStr := hex.EncodeToString(keyRecord.Serialize())
	js.Global().Get("signalDao").Call("saveSenderKey", senderKeyName.GroupID(), senderKeyName.Sender().String(), recordStr)
}

func (i *MixinSenderKeyStore) LoadSenderKey(senderKeyName *protocol.SenderKeyName) *groupRecord.SenderKey {
	result := js.Global().Get("signalDao").Call("getSenderKey", senderKeyName.GroupID(), senderKeyName.Sender().String())
	if result.IsUndefined() {
		return groupRecord.NewSenderKey(i.serializer, i.stateSerializer)
	}
	recordResult := result.Get("record")
	serialized, err := hex.DecodeString(recordResult.String())
	if err != nil {
		fmt.Println(err)
		return nil
	}
	senderKey, err := groupRecord.NewSenderKeyFromBytes(serialized, i.serializer, i.stateSerializer)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return senderKey
}
