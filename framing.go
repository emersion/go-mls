package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type protocolVersion uint16

const (
	protocolVersionMLS10 protocolVersion = 1
)

type contentType uint8

const (
	contentTypeApplication contentType = 1
	contentTypeProposal    contentType = 2
	contentTypeCommit      contentType = 3
)

func (ct *contentType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(ct)) {
		return io.ErrUnexpectedEOF
	}
	switch *ct {
	case contentTypeApplication, contentTypeProposal, contentTypeCommit:
		return nil
	default:
		return fmt.Errorf("mls: invalid content type %d", *ct)
	}
}

func (ct contentType) marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(ct))
}

type senderType uint8

const (
	senderTypeMember            senderType = 1
	senderTypeExternal          senderType = 2
	senderTypeNewMemberProposal senderType = 3
	senderTypeNewMemberCommit   senderType = 4
)

func (st *senderType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(st)) {
		return io.ErrUnexpectedEOF
	}
	switch *st {
	case senderTypeMember, senderTypeExternal, senderTypeNewMemberProposal, senderTypeNewMemberCommit:
		return nil
	default:
		return fmt.Errorf("mls: invalid sender type %d", *st)
	}
}

func (st senderType) marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(st))
}

type sender struct {
	senderType  senderType
	leafIndex   leafIndex // for senderTypeMember
	senderIndex uint32    // for senderTypeExternal
}

func (snd *sender) unmarshal(s *cryptobyte.String) error {
	*snd = sender{}
	if err := snd.senderType.unmarshal(s); err != nil {
		return err
	}
	switch snd.senderType {
	case senderTypeMember:
		if !s.ReadUint32((*uint32)(&snd.leafIndex)) {
			return io.ErrUnexpectedEOF
		}
	case senderTypeExternal:
		if !s.ReadUint32(&snd.senderIndex) {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (snd *sender) marshal(b *cryptobyte.Builder) {
	snd.senderType.marshal(b)
	switch snd.senderType {
	case senderTypeMember:
		b.AddUint32(uint32(snd.leafIndex))
	case senderTypeExternal:
		b.AddUint32(snd.senderIndex)
	}
}

type wireFormat uint16

// http://www.iana.org/assignments/mls/mls.xhtml#mls-wire-formats
const (
	wireFormatMLSPublicMessage  wireFormat = 0x0001
	wireFormatMLSPrivateMessage wireFormat = 0x0002
	wireFormatMLSWelcome        wireFormat = 0x0003
	wireFormatMLSGroupInfo      wireFormat = 0x0004
	wireFormatMLSKeyPackage     wireFormat = 0x0005
)

func (wf *wireFormat) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint16((*uint16)(wf)) {
		return io.ErrUnexpectedEOF
	}
	switch *wf {
	case wireFormatMLSPublicMessage, wireFormatMLSPrivateMessage, wireFormatMLSWelcome, wireFormatMLSGroupInfo, wireFormatMLSKeyPackage:
		return nil
	default:
		return fmt.Errorf("mls: invalid wire format %d", *wf)
	}
}

// GroupID is an application-specific group identifier.
type GroupID []byte

type framedContent struct {
	groupID           GroupID
	epoch             uint64
	sender            sender
	authenticatedData []byte

	contentType     contentType
	applicationData []byte    // for contentTypeApplication
	proposal        *proposal // for contentTypeProposal
	commit          *commit   // for contentTypeCommit
}

func (content *framedContent) unmarshal(s *cryptobyte.String) error {
	*content = framedContent{}

	if !readOpaqueVec(s, (*[]byte)(&content.groupID)) || !s.ReadUint64(&content.epoch) {
		return io.ErrUnexpectedEOF
	}
	if err := content.sender.unmarshal(s); err != nil {
		return err
	}
	if !readOpaqueVec(s, &content.authenticatedData) {
		return io.ErrUnexpectedEOF
	}
	if err := content.contentType.unmarshal(s); err != nil {
		return err
	}

	switch content.contentType {
	case contentTypeApplication:
		if !readOpaqueVec(s, &content.applicationData) {
			return io.ErrUnexpectedEOF
		}
		return nil
	case contentTypeProposal:
		content.proposal = new(proposal)
		return content.proposal.unmarshal(s)
	case contentTypeCommit:
		content.commit = new(commit)
		return content.commit.unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (content *framedContent) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(content.groupID))
	b.AddUint64(content.epoch)
	content.sender.marshal(b)
	writeOpaqueVec(b, content.authenticatedData)
	content.contentType.marshal(b)
	switch content.contentType {
	case contentTypeApplication:
		writeOpaqueVec(b, content.applicationData)
	case contentTypeProposal:
		content.proposal.marshal(b)
	case contentTypeCommit:
		content.commit.marshal(b)
	default:
		panic("unreachable")
	}
}

type mlsMessage struct {
	version        protocolVersion
	wireFormat     wireFormat
	publicMessage  *publicMessage  // for wireFormatMLSPublicMessage
	privateMessage *privateMessage // for wireFormatMLSPrivateMessage
	welcome        *welcome        // for wireFormatMLSWelcome
	groupInfo      *groupInfo      // for wireFormatMLSGroupInfo
	keyPackage     *keyPackage     // for wireFormatMLSKeyPackage
}

func (msg *mlsMessage) unmarshal(s *cryptobyte.String) error {
	*msg = mlsMessage{}

	if !s.ReadUint16((*uint16)(&msg.version)) {
		return io.ErrUnexpectedEOF
	}
	if msg.version != protocolVersionMLS10 {
		return fmt.Errorf("mls: invalid protocol version %d", msg.version)
	}

	if err := msg.wireFormat.unmarshal(s); err != nil {
		return err
	}

	switch msg.wireFormat {
	case wireFormatMLSPublicMessage:
		msg.publicMessage = new(publicMessage)
		return msg.publicMessage.unmarshal(s)
	case wireFormatMLSPrivateMessage:
		msg.privateMessage = new(privateMessage)
		return msg.privateMessage.unmarshal(s)
	case wireFormatMLSWelcome:
		msg.welcome = new(welcome)
		return msg.welcome.unmarshal(s)
	case wireFormatMLSGroupInfo:
		msg.groupInfo = new(groupInfo)
		return msg.groupInfo.unmarshal(s)
	case wireFormatMLSKeyPackage:
		msg.keyPackage = new(keyPackage)
		return msg.keyPackage.unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (msg *mlsMessage) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(msg.version))
	b.AddUint16(uint16(msg.wireFormat))
	switch msg.wireFormat {
	case wireFormatMLSGroupInfo:
		msg.groupInfo.marshal(b)
	case wireFormatMLSKeyPackage:
		msg.keyPackage.marshal(b)
	default:
		b.SetError(fmt.Errorf("TODO: mlsMessage.marshal"))
	}
}

type authenticatedContent struct {
	wireFormat wireFormat
	content    framedContent
	auth       framedContentAuthData
}

type framedContentAuthData struct {
	signature       []byte
	confirmationTag []byte // for contentTypeCommit
}

func (authData *framedContentAuthData) unmarshal(s *cryptobyte.String, ct contentType) error {
	*authData = framedContentAuthData{}

	if !readOpaqueVec(s, &authData.signature) {
		return io.ErrUnexpectedEOF
	}

	if ct == contentTypeCommit {
		if !readOpaqueVec(s, &authData.confirmationTag) {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}

func (authData *framedContentAuthData) verify(cs cipherSuite, verifKey []byte, content *framedContentTBS) bool {
	// TODO: check confirmationTag
	rawContent, err := marshal(content)
	if err != nil {
		return false
	}
	return cs.verifyWithLabel(verifKey, []byte("FramedContentTBS"), rawContent, authData.signature)
}

type framedContentTBS struct {
	version    protocolVersion
	wireFormat wireFormat
	content    framedContent
	context    *groupContext // for senderTypeMember and senderTypeNewMemberCommit
}

func (content *framedContentTBS) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(content.version))
	b.AddUint16(uint16(content.wireFormat))
	content.content.marshal(b)
	switch content.content.sender.senderType {
	case senderTypeMember, senderTypeNewMemberCommit:
		content.context.marshal(b)
	}
}

type publicMessage struct {
	content       framedContent
	auth          framedContentAuthData
	membershipTag []byte // for senderTypeMember
}

func (msg *publicMessage) unmarshal(s *cryptobyte.String) error {
	*msg = publicMessage{}

	if err := msg.content.unmarshal(s); err != nil {
		return err
	}
	if err := msg.auth.unmarshal(s, msg.content.contentType); err != nil {
		return err
	}

	if msg.content.sender.senderType == senderTypeMember {
		if !readOpaqueVec(s, &msg.membershipTag) {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}

// TODO: add membershipTag verification

type privateMessage struct {
	groupID             GroupID
	epoch               uint64
	contentType         contentType
	authenticatedData   []byte
	encryptedSenderData []byte
	ciphertext          []byte
}

func (msg *privateMessage) unmarshal(s *cryptobyte.String) error {
	*msg = privateMessage{}
	ok := readOpaqueVec(s, (*[]byte)(&msg.groupID)) &&
		s.ReadUint64(&msg.epoch)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	if err := msg.contentType.unmarshal(s); err != nil {
		return err
	}
	ok = readOpaqueVec(s, &msg.authenticatedData) &&
		readOpaqueVec(s, &msg.encryptedSenderData) &&
		readOpaqueVec(s, &msg.ciphertext)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (msg *privateMessage) decryptSenderData(cs cipherSuite, senderDataSecret []byte) (*senderData, error) {
	key, err := expandSenderDataKey(cs, senderDataSecret, msg.ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := expandSenderDataNonce(cs, senderDataSecret, msg.ciphertext)
	if err != nil {
		return nil, err
	}

	rawAAD, err := marshal((*senderDataAAD)(msg))
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawSenderData, err := cipher.Open(nil, nonce, msg.encryptedSenderData, rawAAD)
	if err != nil {
		return nil, err
	}

	var senderData senderData
	if err := unmarshal(rawSenderData, &senderData); err != nil {
		return nil, err
	}

	return &senderData, nil
}

func (msg *privateMessage) decryptContent(cs cipherSuite, secret ratchetSecret, reuseGuard [4]byte) (*privateMessageContent, error) {
	key, err := secret.deriveKey(cs)
	if err != nil {
		return nil, err
	}
	nonce, err := secret.deriveNonce(cs)
	if err != nil {
		return nil, err
	}

	for i := range reuseGuard {
		nonce[i] = nonce[i] ^ reuseGuard[i]
	}

	rawAAD, err := marshal((*privateContentAAD)(msg))
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawContent, err := cipher.Open(nil, nonce, msg.ciphertext, rawAAD)
	if err != nil {
		return nil, err
	}

	s := cryptobyte.String(rawContent)
	var content privateMessageContent
	if err := content.unmarshal(&s, msg.contentType); err != nil {
		return nil, err
	}

	for _, v := range s {
		if v != 0 {
			return nil, fmt.Errorf("mls: padding contains non-zero bytes")
		}
	}

	// TODO: check framedContentAuthData

	return &content, nil
}

type senderDataAAD privateMessage

func (aad *senderDataAAD) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(aad.groupID))
	b.AddUint64(aad.epoch)
	aad.contentType.marshal(b)
}

type privateContentAAD privateMessage

func (aad *privateContentAAD) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(aad.groupID))
	b.AddUint64(aad.epoch)
	aad.contentType.marshal(b)
	writeOpaqueVec(b, aad.authenticatedData)
}

type privateMessageContent struct {
	applicationData []byte    // for contentTypeApplication
	proposal        *proposal // for contentTypeProposal
	commit          *commit   // for contentTypeCommit

	auth framedContentAuthData
}

func (content *privateMessageContent) unmarshal(s *cryptobyte.String, ct contentType) error {
	*content = privateMessageContent{}

	var err error
	switch ct {
	case contentTypeApplication:
		if !readOpaqueVec(s, &content.applicationData) {
			err = io.ErrUnexpectedEOF
		}
	case contentTypeProposal:
		content.proposal = new(proposal)
		err = content.proposal.unmarshal(s)
	case contentTypeCommit:
		content.commit = new(commit)
		err = content.commit.unmarshal(s)
	default:
		panic("unreachable")
	}
	if err != nil {
		return err
	}

	return content.auth.unmarshal(s, ct)
}

type senderData struct {
	leafIndex  leafIndex
	generation uint32
	reuseGuard [4]byte
}

func (data *senderData) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint32((*uint32)(&data.leafIndex)) || !s.ReadUint32(&data.generation) || !s.CopyBytes(data.reuseGuard[:]) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func expandSenderDataKey(cs cipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.expandWithLabel(senderDataSecret, []byte("key"), ciphertextSample, uint16(aead.KeySize()))
}

func expandSenderDataNonce(cs cipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.expandWithLabel(senderDataSecret, []byte("nonce"), ciphertextSample, uint16(aead.NonceSize()))
}

func sampleCiphertext(cs cipherSuite, ciphertext []byte) []byte {
	_, kdf, _ := cs.hpke().Params()
	n := kdf.ExtractSize()
	if len(ciphertext) < n {
		return ciphertext
	}
	return ciphertext[:n]
}
