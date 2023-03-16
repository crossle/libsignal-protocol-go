package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"syscall/js"

	"github.com/crossle/libsignal-protocol-go/ecc"
	"github.com/crossle/libsignal-protocol-go/groups"
	"github.com/crossle/libsignal-protocol-go/keys/identity"
	"github.com/crossle/libsignal-protocol-go/keys/prekey"
	"github.com/crossle/libsignal-protocol-go/logger"
	"github.com/crossle/libsignal-protocol-go/protocol"
	"github.com/crossle/libsignal-protocol-go/provision"
	"github.com/crossle/libsignal-protocol-go/serialize"
	"github.com/crossle/libsignal-protocol-go/session"
	"github.com/crossle/libsignal-protocol-go/util/bytehelper"
	"github.com/crossle/libsignal-protocol-go/util/keyhelper"
	"github.com/crossle/libsignal-protocol-go/util/optional"
)

var serializer = serialize.NewProtoBufSerializer()

func generateIdentityKeyPair(this js.Value, args []js.Value) interface{} {
	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		logger.Error(err)
		return nil
	}
	publicKey := identityKeyPair.PublicKey().Serialize()
	privateKey := identityKeyPair.PrivateKey().Serialize()
	pub := base64.StdEncoding.EncodeToString(publicKey)
	priv := base64.StdEncoding.EncodeToString(privateKey[:])
	return map[string]interface{}{"pub": pub, "priv": priv}
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	keyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		logger.Error(err)
		return nil
	}
	public := keyPair.PublicKey().Serialize()
	private := keyPair.PrivateKey().Serialize()
	pub := base64.StdEncoding.EncodeToString(public)
	priv := base64.StdEncoding.EncodeToString(private[:])
	return map[string]interface{}{"pub": pub, "priv": priv}
}

func createKeyPair(this js.Value, args []js.Value) interface{} {
	privateKey := args[0].String()
	decoded, _ := base64.StdEncoding.DecodeString(privateKey)
	keyPair := ecc.CreateKeyPair(decoded)

	publicKey := identity.NewKey(keyPair.PublicKey())
	identityKeyPair := identity.NewKeyPair(publicKey, keyPair.PrivateKey())

	public := identityKeyPair.PublicKey().Serialize()
	private := identityKeyPair.PrivateKey().Serialize()
	pub := base64.StdEncoding.EncodeToString(public)
	priv := base64.StdEncoding.EncodeToString(private[:])
	return map[string]interface{}{"pub": pub, "priv": priv}
}

func generateRegId(this js.Value, args []js.Value) interface{} {
	return keyhelper.GenerateRegistrationID()
}

func generateSignedPreKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return nil
	}
	pub, priv, id := args[0], args[1], args[2]
	public, _ := base64.StdEncoding.DecodeString(pub.String())
	private, _ := base64.StdEncoding.DecodeString(priv.String())

	publicKeyable, _ := ecc.DecodePoint(public, 0)
	publicKey := identity.NewKey(publicKeyable)
	privateKey := ecc.NewDjbECPrivateKey(bytehelper.SliceToArray(private))
	identityKeyPair := identity.NewKeyPair(publicKey, privateKey)
	signedPeKey, _ := keyhelper.GenerateSignedPreKey(identityKeyPair, uint32(id.Int()), serializer.SignedPreKeyRecord)
	return string(signedPeKey.Serialize())
}

func generatePreKeys(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return nil
	}
	start, end := args[0].Int(), args[1].Int()
	preKeys, err := keyhelper.GeneratePreKeys(start, end, serializer.PreKeyRecord)
	if err != nil {
		logger.Error(err)
		return nil
	}
	var encodePreKeys []string
	for _, preKey := range preKeys {
		encodePreKeys = append(encodePreKeys, hex.EncodeToString(preKey.Serialize()))
	}
	return strings.Join(encodePreKeys, ",")
}

func containsSession(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return nil
	}
	name, deviceId := args[0].String(), args[1].Int()
	sessionStore := NewMixinSessionStore(serializer)
	result := sessionStore.ContainsSession(protocol.NewSignalAddress(name, uint32(deviceId)))
	return result
}

type ConsumeSignedPreKey struct {
	KeyId     int    `json:"key_id"`
	PubKey    []byte `json:"pub_key"`
	Signature []byte `json:"signature"`
}

type ConsumeOneTimeKey struct {
	KeyId  int    `json:"key_id,omitempty"`
	PubKey []byte `json:"pub_key,omitempty"`
}

type ConsumePreKeyBundle struct {
	UserId         string              `json:"user_id"`
	RegistrationId int                 `json:"registration_id"`
	IdentityKey    []byte              `json:"identity_key"`
	Signed         ConsumeSignedPreKey `json:"signed_pre_key"`
	OnetimeKey     ConsumeOneTimeKey   `json:"one_time_pre_key"`
}

func processSession(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return nil
	}
	name, deviceId, bundle := args[0].String(), args[1].Int(), args[2].String()

	var preKeyBundle ConsumePreKeyBundle
	err := json.Unmarshal([]byte(bundle), &preKeyBundle)
	if err != nil {
		logger.Error(err)
		return nil
	}
	var preKeyPublic ecc.ECPublicKeyable
	if preKeyBundle.OnetimeKey.PubKey != nil && len(preKeyBundle.OnetimeKey.PubKey) > 0 {
		preKeyPublic, _ = ecc.DecodePoint(preKeyBundle.OnetimeKey.PubKey, 0)
	}
	var oneTimeKeyId *optional.Uint32
	if preKeyBundle.OnetimeKey.KeyId == 0 {
		oneTimeKeyId = optional.NewEmptyUint32()
	} else {
		oneTimeKeyId = optional.NewOptionalUint32(uint32(preKeyBundle.OnetimeKey.KeyId))
	}
	signedPreKeyPublic, err := ecc.DecodePoint(preKeyBundle.Signed.PubKey, 0)
	if err != nil {
		logger.Error(err)
		return nil
	}
	signature := bytehelper.SliceToArray64(preKeyBundle.Signed.Signature)
	publicKeyable, _ := ecc.DecodePoint(preKeyBundle.IdentityKey, 0)
	identityKey := identity.NewKey(publicKeyable)

	retrievedPreKey := prekey.NewBundle(uint32(preKeyBundle.RegistrationId), uint32(deviceId),
		oneTimeKeyId, uint32(preKeyBundle.Signed.KeyId),
		preKeyPublic, signedPreKeyPublic, signature, identityKey)

	signalProtocolStore := NewMixinSignalProtocolStore(serializer)
	remoteAddress := protocol.NewSignalAddress(name, uint32(deviceId))
	sessionBuilder := session.NewBuilderFromSignal(
		signalProtocolStore,
		remoteAddress,
		serializer,
	)
	err = sessionBuilder.ProcessBundle(retrievedPreKey)
	if err != nil {
		logger.Error(err)
		return false
	}
	return true
}

func encryptSenderKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 5 {
		return nil
	}
	groupId := args[0].String()
	recipientId, recipientDeviceId := args[1].String(), args[2].Int()
	senderId, senderDeviceId := args[3].String(), args[4].Int()

	address := protocol.NewSignalAddress(senderId, uint32(senderDeviceId))
	senderKeyName := protocol.NewSenderKeyName(groupId, address)

	senderKeyStore := NewMixinSenderKeyStore(serializer)
	builder := groups.NewGroupSessionBuilder(senderKeyStore, serializer)
	senderKeyDistributionMessage, err := builder.Create(senderKeyName)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	remoteAddress := protocol.NewSignalAddress(recipientId, uint32(recipientDeviceId))
	ciphertextMessage, err := encryptSession(senderKeyDistributionMessage.Serialize(), remoteAddress)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return encodeMessageData(ciphertextMessage.Type(), ciphertextMessage.Serialize(), "")
}

func encryptSessionMessage(this js.Value, args []js.Value) interface{} {
	recipientId := args[0].String()
	recipientDeviceId := args[1].Int()
	plaintext := args[2].String()
	messageId := args[3].String()
	remoteAddress := protocol.NewSignalAddress(recipientId, uint32(recipientDeviceId))
	ciphertextMessage, err := encryptSession([]byte(plaintext), remoteAddress)
	if err != nil {
		logger.Error(err)
		return nil
	}
	return encodeMessageData(ciphertextMessage.Type(), ciphertextMessage.Serialize(), messageId)
}

func encryptSession(plaintext []byte, remoteAddress *protocol.SignalAddress) (protocol.CiphertextMessage, error) {
	signalProtocolStore := NewMixinSignalProtocolStore(serializer)
	buidler := session.NewBuilderFromSignal(signalProtocolStore, remoteAddress, serializer)
	sessionCipher := session.NewCipher(buidler, remoteAddress)
	ciphertextMessage, err := sessionCipher.Encrypt(plaintext)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	return ciphertextMessage, nil
}

func encodeMessageData(keyType uint32, cipher []byte, resendMessageId string) string {
	if resendMessageId == "" {
		header := []byte{byte(protocol.CurrentVersion), byte(keyType), 0, 0, 0, 0, 0, 0}
		ciphertext := append(header, cipher...)
		return base64.StdEncoding.EncodeToString(ciphertext)
	} else {
		header := []byte{byte(protocol.CurrentVersion), byte(keyType), 1, 0, 0, 0, 0, 0}
		header = append(header, []byte(resendMessageId)...)
		ciphertext := append(header, cipher...)
		result := base64.StdEncoding.EncodeToString(ciphertext)
		return result
	}
}

func encryptGroupMessage(this js.Value, args []js.Value) interface{} {
	if len(args) != 4 {
		return nil
	}
	groupId := args[0].String()
	senderId, senderDeviceId := args[1].String(), args[2].Int()
	plaintext := args[3].String()

	sender := protocol.NewSignalAddress(senderId, uint32(senderDeviceId))
	senderKeyName := protocol.NewSenderKeyName(groupId, sender)

	senderKeyStore := NewMixinSenderKeyStore(serializer)
	builder := groups.NewGroupSessionBuilder(senderKeyStore, serializer)
	groupCipher := groups.NewGroupCipher(builder, senderKeyName, senderKeyStore)
	cipherMessage, err := groupCipher.Encrypt([]byte(plaintext))
	if err != nil {
		fmt.Println(err)
		return nil
	}
	message := cipherMessage.(*protocol.SenderKeyMessage)
	return encodeMessageData(message.Type(), message.SignedSerialize(), "")
}

func isExistSenderKey(this js.Value, args []js.Value) interface{} {
	groupId := args[0].String()
	senderId, senderDeviceId := args[1].String(), args[2].Int()
	sender := protocol.NewSignalAddress(senderId, uint32(senderDeviceId))
	senderKeyName := protocol.NewSenderKeyName(groupId, sender)
	senderKeyStore := NewMixinSenderKeyStore(serializer)
	senderKey := senderKeyStore.LoadSenderKey(senderKeyName)
	return !senderKey.IsEmpty()
}

func decryptEncodeMessage(this js.Value, args []js.Value) interface{} {
	if len(args) != 5 {
		return nil
	}
	groupId := args[0].String()
	senderId, deviceId := args[1].String(), args[2].Int()
	data := args[3].String()
	category := args[4].String()
	cipherText, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	header := cipherText[0:7]
	version := int(header[0])
	if version != protocol.CurrentVersion {
		return nil
	}
	dataType := int(header[1])
	isResendMessage := int(header[2]) == 1
	var rawData []byte
	if isResendMessage {
		_ = cipherText[8:43]
		rawData = cipherText[44:]
	} else {
		rawData = cipherText[8:]
	}

	senderAddress := protocol.NewSignalAddress(senderId, uint32(deviceId))

	signalProtocolStore := NewMixinSignalProtocolStore(serializer)
	builder := session.NewBuilderFromSignal(signalProtocolStore, senderAddress, serializer)
	sessionCipher := session.NewCipher(builder, senderAddress)

	if category == "SIGNAL_KEY" {
		if dataType == protocol.PREKEY_TYPE {
			receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(rawData, serializer.PreKeySignalMessage, serializer.SignalMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			plaintext, err := sessionCipher.DecryptMessage(receivedMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			err = processGroupSession(groupId, senderAddress, plaintext)
			if err != nil {
				logger.Error(err)
				return nil
			}
			return true
		} else if dataType == protocol.WHISPER_TYPE {
			encryptedMessage, err := protocol.NewSignalMessageFromBytes(rawData, serializer.SignalMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			plaintext, err := sessionCipher.Decrypt(encryptedMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			err = processGroupSession(groupId, senderAddress, plaintext)
			if err != nil {
				logger.Error(err)
				return nil
			}
			return true
		}
	} else {
		if dataType == protocol.PREKEY_TYPE {
			receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(rawData, serializer.PreKeySignalMessage, serializer.SignalMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			plaintext, err := sessionCipher.DecryptMessage(receivedMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			return string(plaintext)
		} else if dataType == protocol.WHISPER_TYPE {
			encryptedMessage, err := protocol.NewSignalMessageFromBytes(rawData, serializer.SignalMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			plaintext, err := sessionCipher.Decrypt(encryptedMessage)
			if err != nil {
				logger.Error(err)
				return nil
			}
			return string(plaintext)
		} else if dataType == protocol.SENDERKEY_TYPE {
			plaintext, err := decryptGroupMessage(groupId, senderAddress, rawData)
			if err != nil {
				return nil
			}
			return string(plaintext)
		}
	}
	return nil
}

func processGroupSession(groupId string, address *protocol.SignalAddress, msg []byte) error {
	senderKeyStore := NewMixinSenderKeyStore(serializer)
	skdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(msg, serializer.SenderKeyDistributionMessage)
	if err != nil {
		return err
	}
	senderKeyName := protocol.NewSenderKeyName(groupId, address)
	builder := groups.NewGroupSessionBuilder(senderKeyStore, serializer)
	builder.Process(senderKeyName, skdm)
	return nil
}

func decryptGroupMessage(groupId string, address *protocol.SignalAddress, cipherText []byte) ([]byte, error) {
	senderKeyName := protocol.NewSenderKeyName(groupId, address)

	senderKeyStore := NewMixinSenderKeyStore(serializer)
	builder := groups.NewGroupSessionBuilder(senderKeyStore, serializer)
	groupCipher := groups.NewGroupCipher(builder, senderKeyName, senderKeyStore)

	encryptedMessage, err := protocol.NewSenderKeyMessageFromBytes(cipherText, serializer.SenderKeyMessage)
	plaintext, err := groupCipher.Decrypt(encryptedMessage)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return plaintext, nil
}

func sessionIdToDeviceId(sessionId string) int32 {
	components := strings.Split(sessionId, "-")
	for i, x := range components {
		components[i] = "0x" + x
	}
	mostSigBits, _ := strconv.ParseInt(components[0], 0, 64)
	mostSigBits <<= 16
	c1, _ := strconv.ParseInt(components[1], 0, 64)
	mostSigBits |= c1
	mostSigBits <<= 16
	c2, _ := strconv.ParseInt(components[2], 0, 64)
	mostSigBits |= c2

	leastSigBits, _ := strconv.ParseInt(components[3], 0, 64)
	leastSigBits <<= 48
	c4, _ := strconv.ParseInt(components[4], 0, 64)
	leastSigBits |= c4

	hilo := mostSigBits ^ leastSigBits
	result := (int32((hilo >> 32))) ^ int32(hilo)
	if result < 0 {
		return -result
	}
	return result
}

func uuidHashCode(this js.Value, args []js.Value) interface{} {
	name := args[0].String()
	return sessionIdToDeviceId(name)
}

func decryptProvision(this js.Value, args []js.Value) interface{} {
	priv, content := args[0].String(), args[1].String()
	plaintext, err := provision.Decrypt(priv, content)
	if err != nil {
		logger.Error(err)
		return err
	}
	return plaintext
}

func decryptAttachment(this js.Value, args []js.Value) interface{} {
	return nil
}

func registerCallbacks() {
	js.Global().Set("generateIdentityKeyPaireFromGo", js.FuncOf(generateIdentityKeyPair))
	js.Global().Set("generateKeyPairFromGo", js.FuncOf(generateKeyPair))
	js.Global().Set("generateSignedPreKeyFromGo", js.FuncOf(generateSignedPreKey))
	js.Global().Set("generatePreKeysFromGo", js.FuncOf(generatePreKeys))
	js.Global().Set("generateRegIdFromGo", js.FuncOf(generateRegId))
	js.Global().Set("createKeyPairFromGo", js.FuncOf(createKeyPair))

	js.Global().Set("containsSessionFromGo", js.FuncOf(containsSession))
	js.Global().Set("processSessionFromGo", js.FuncOf(processSession))
	js.Global().Set("encryptSenderKeyFromGo", js.FuncOf(encryptSenderKey))
	js.Global().Set("encryptGroupMessageFromGo", js.FuncOf(encryptGroupMessage))
	js.Global().Set("encryptSessionMessageFromGo", js.FuncOf(encryptSessionMessage))
	js.Global().Set("isExistSenderKeyFromGo", js.FuncOf(isExistSenderKey))
	js.Global().Set("decryptEncodedMessageFromGo", js.FuncOf(decryptEncodeMessage))
	js.Global().Set("uuidHashCodeFromGo", js.FuncOf(uuidHashCode))

	js.Global().Set("decryptProvisionFromGo", js.FuncOf(decryptProvision))

	js.Global().Set("decryptAttachmentFromGo", js.FuncOf(decryptAttachment))
}

func main() {
	c := make(chan struct{}, 0)
	registerCallbacks()
	<-c
}
