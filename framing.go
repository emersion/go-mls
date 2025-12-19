package mls

import (
	"bytes"
	"crypto/rand"
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

func (wf wireFormat) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(wf))
}

// GroupID is an application-specific group identifier.
type GroupID []byte

// Equal checks whether two key package references are equal.
func (ref GroupID) Equal(other GroupID) bool {
	return bytes.Equal([]byte(ref), []byte(other))
}

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
	welcome        *Welcome        // for wireFormatMLSWelcome
	groupInfo      *groupInfo      // for wireFormatMLSGroupInfo
	keyPackage     *KeyPackage     // for wireFormatMLSKeyPackage
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
		msg.welcome = new(Welcome)
		return msg.welcome.unmarshal(s)
	case wireFormatMLSGroupInfo:
		msg.groupInfo = new(groupInfo)
		return msg.groupInfo.unmarshal(s)
	case wireFormatMLSKeyPackage:
		msg.keyPackage = new(KeyPackage)
		return msg.keyPackage.unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (msg *mlsMessage) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(msg.version))
	msg.wireFormat.marshal(b)
	switch msg.wireFormat {
	case wireFormatMLSPublicMessage:
		msg.publicMessage.marshal(b)
	case wireFormatMLSPrivateMessage:
		msg.privateMessage.marshal(b)
	case wireFormatMLSWelcome:
		msg.welcome.marshal(b)
	case wireFormatMLSGroupInfo:
		msg.groupInfo.marshal(b)
	case wireFormatMLSKeyPackage:
		msg.keyPackage.marshal(b)
	default:
		panic("unreachable")
	}
}

type authenticatedContent struct {
	wireFormat wireFormat
	content    framedContent
	auth       framedContentAuthData
}

func signAuthenticatedContent(cs CipherSuite, signKey signaturePrivateKey, wf wireFormat, content *framedContent, ctx *groupContext) (*authenticatedContent, error) {
	authContent := authenticatedContent{
		wireFormat: wf,
		content:    *content,
	}
	tbs := authContent.framedContentTBS(ctx)
	signature, err := signFramedContent(cs, signKey, tbs)
	if err != nil {
		return nil, err
	}
	authContent.auth.signature = signature
	return &authContent, nil
}

func (authContent *authenticatedContent) unmarshal(s *cryptobyte.String) error {
	if err := authContent.wireFormat.unmarshal(s); err != nil {
		return err
	}
	if err := authContent.content.unmarshal(s); err != nil {
		return err
	}
	if err := authContent.auth.unmarshal(s, authContent.content.contentType); err != nil {
		return err
	}
	return nil
}

func (authContent *authenticatedContent) marshal(b *cryptobyte.Builder) {
	authContent.wireFormat.marshal(b)
	authContent.content.marshal(b)
	authContent.auth.marshal(b, authContent.content.contentType)
}

func (authContent *authenticatedContent) confirmedTranscriptHashInput() *confirmedTranscriptHashInput {
	return &confirmedTranscriptHashInput{
		wireFormat: authContent.wireFormat,
		content:    authContent.content,
		signature:  authContent.auth.signature,
	}
}

func (authContent *authenticatedContent) framedContentTBS(ctx *groupContext) *framedContentTBS {
	return &framedContentTBS{
		version:    protocolVersionMLS10,
		wireFormat: authContent.wireFormat,
		content:    authContent.content,
		context:    ctx,
	}
}

func (authContent *authenticatedContent) verifySignature(verifKey signaturePublicKey, ctx *groupContext) bool {
	return authContent.auth.verifySignature(ctx.cipherSuite, verifKey, authContent.framedContentTBS(ctx))
}

func (authContent *authenticatedContent) generateProposalRef(cs CipherSuite) (proposalRef, error) {
	if authContent.content.contentType != contentTypeProposal {
		panic("mls: AuthenticatedContent is not a proposal")
	}

	var b cryptobyte.Builder
	authContent.marshal(&b)
	raw, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	hash, err := cs.refHash([]byte("MLS 1.0 Proposal Reference"), raw)
	if err != nil {
		return nil, err
	}

	return proposalRef(hash), nil
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

func (authData *framedContentAuthData) marshal(b *cryptobyte.Builder, ct contentType) {
	writeOpaqueVec(b, authData.signature)

	if ct == contentTypeCommit {
		writeOpaqueVec(b, authData.confirmationTag)
	}
}

func (authData *framedContentAuthData) verifyConfirmationTag(cs CipherSuite, confirmationKey, confirmedTranscriptHash []byte) bool {
	if len(authData.confirmationTag) == 0 {
		return false
	}
	return cs.verifyMAC(confirmationKey, confirmedTranscriptHash, authData.confirmationTag)
}

func (authData *framedContentAuthData) verifySignature(cs CipherSuite, verifKey signaturePublicKey, content *framedContentTBS) bool {
	rawContent, err := marshal(content)
	if err != nil {
		return false
	}
	return cs.verifyWithLabel(verifKey, []byte("FramedContentTBS"), rawContent, authData.signature)
}

func signFramedContent(cs CipherSuite, signKey signaturePrivateKey, content *framedContentTBS) ([]byte, error) {
	rawContent, err := marshal(content)
	if err != nil {
		return nil, err
	}
	return cs.signWithLabel(signKey, []byte("FramedContentTBS"), rawContent)
}

type framedContentTBS struct {
	version    protocolVersion
	wireFormat wireFormat
	content    framedContent
	context    *groupContext // for senderTypeMember and senderTypeNewMemberCommit
}

func (content *framedContentTBS) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(content.version))
	content.wireFormat.marshal(b)
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

func signPublicMessage(cs CipherSuite, signKey signaturePrivateKey, content *framedContent, ctx *groupContext) (*publicMessage, error) {
	authContent, err := signAuthenticatedContent(cs, signKey, wireFormatMLSPublicMessage, content, ctx)
	if err != nil {
		return nil, err
	}
	return &publicMessage{
		content: authContent.content,
		auth:    authContent.auth,
	}, nil
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

func (msg *publicMessage) marshal(b *cryptobyte.Builder) {
	msg.content.marshal(b)
	msg.auth.marshal(b, msg.content.contentType)

	if msg.content.sender.senderType == senderTypeMember {
		writeOpaqueVec(b, msg.membershipTag)
	}
}

func (msg *publicMessage) authenticatedContent() *authenticatedContent {
	return &authenticatedContent{
		wireFormat: wireFormatMLSPublicMessage,
		content:    msg.content,
		auth:       msg.auth,
	}
}

func (msg *publicMessage) authenticatedContentTBM(ctx *groupContext) *authenticatedContentTBM {
	return &authenticatedContentTBM{
		contentTBS: *msg.authenticatedContent().framedContentTBS(ctx),
		auth:       msg.auth,
	}
}

func (msg *publicMessage) signMembershipTag(cs CipherSuite, membershipKey []byte, ctx *groupContext) error {
	if msg.content.sender.senderType != senderTypeMember {
		return nil
	}
	rawAuthContentTBM, err := marshal(msg.authenticatedContentTBM(ctx))
	if err != nil {
		return err
	}
	msg.membershipTag = cs.signMAC(membershipKey, rawAuthContentTBM)
	return nil
}

func (msg *publicMessage) verifyMembershipTag(membershipKey []byte, ctx *groupContext) bool {
	if msg.content.sender.senderType != senderTypeMember {
		return true // there is no membership tag
	}
	rawAuthContentTBM, err := marshal(msg.authenticatedContentTBM(ctx))
	if err != nil {
		return false
	}
	return ctx.cipherSuite.verifyMAC(membershipKey, rawAuthContentTBM, msg.membershipTag)
}

type authenticatedContentTBM struct {
	contentTBS framedContentTBS
	auth       framedContentAuthData
}

func (tbm *authenticatedContentTBM) marshal(b *cryptobyte.Builder) {
	tbm.contentTBS.marshal(b)
	tbm.auth.marshal(b, tbm.contentTBS.content.contentType)
}

type privateMessage struct {
	groupID             GroupID
	epoch               uint64
	contentType         contentType
	authenticatedData   []byte
	encryptedSenderData []byte
	ciphertext          []byte
}

func encryptPrivateMessage(cs CipherSuite, secret ratchetSecret, senderDataSecret []byte, content *framedContent, privContent *privateMessageContent, senderData *senderData) (*privateMessage, error) {
	ciphertext, err := encryptPrivateMessageContent(cs, secret, content, privContent, senderData.reuseGuard)
	if err != nil {
		return nil, err
	}
	encryptedSenderData, err := encryptSenderData(cs, senderDataSecret, senderData, content, ciphertext)
	if err != nil {
		return nil, err
	}
	return &privateMessage{
		groupID:             content.groupID,
		epoch:               content.epoch,
		contentType:         content.contentType,
		authenticatedData:   content.authenticatedData,
		encryptedSenderData: encryptedSenderData,
		ciphertext:          ciphertext,
	}, nil
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

func (msg *privateMessage) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(msg.groupID))
	b.AddUint64(msg.epoch)
	msg.contentType.marshal(b)
	writeOpaqueVec(b, msg.authenticatedData)
	writeOpaqueVec(b, msg.encryptedSenderData)
	writeOpaqueVec(b, msg.ciphertext)
}

func (msg *privateMessage) decryptSenderData(cs CipherSuite, senderDataSecret []byte) (*senderData, error) {
	key, err := expandSenderDataKey(cs, senderDataSecret, msg.ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := expandSenderDataNonce(cs, senderDataSecret, msg.ciphertext)
	if err != nil {
		return nil, err
	}

	aad := senderDataAAD{
		groupID:     msg.groupID,
		epoch:       msg.epoch,
		contentType: msg.contentType,
	}
	rawAAD, err := marshal(&aad)
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

func (msg *privateMessage) decryptContent(cs CipherSuite, secret ratchetSecret, reuseGuard [4]byte) (*privateMessageContent, error) {
	key, nonce, err := derivePrivateMessageKeyAndNonce(cs, secret, reuseGuard)
	if err != nil {
		return nil, err
	}

	aad := privateContentAAD{
		groupID:           msg.groupID,
		epoch:             msg.epoch,
		contentType:       msg.contentType,
		authenticatedData: msg.authenticatedData,
	}
	rawAAD, err := marshal(&aad)
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

	return &content, nil
}

func derivePrivateMessageKeyAndNonce(cs CipherSuite, secret ratchetSecret, reuseGuard [4]byte) (key, nonce []byte, err error) {
	key, err = secret.deriveKey(cs)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = secret.deriveNonce(cs)
	if err != nil {
		return nil, nil, err
	}

	for i := range reuseGuard {
		nonce[i] = nonce[i] ^ reuseGuard[i]
	}

	return key, nonce, nil
}

func (msg *privateMessage) authenticatedContent(senderData *senderData, content *privateMessageContent) *authenticatedContent {
	return content.authenticatedContent(&framedContent{
		groupID: msg.groupID,
		epoch:   msg.epoch,
		sender: sender{
			senderType: senderTypeMember,
			leafIndex:  senderData.leafIndex,
		},
		authenticatedData: msg.authenticatedData,
		contentType:       msg.contentType,
		applicationData:   content.applicationData,
		proposal:          content.proposal,
		commit:            content.commit,
	})
}

type senderDataAAD struct {
	groupID     GroupID
	epoch       uint64
	contentType contentType
}

func (aad *senderDataAAD) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(aad.groupID))
	b.AddUint64(aad.epoch)
	aad.contentType.marshal(b)
}

type privateContentAAD struct {
	groupID           GroupID
	epoch             uint64
	contentType       contentType
	authenticatedData []byte
}

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

func (content *privateMessageContent) marshal(b *cryptobyte.Builder, ct contentType) {
	switch ct {
	case contentTypeApplication:
		writeOpaqueVec(b, content.applicationData)
	case contentTypeProposal:
		content.proposal.marshal(b)
	case contentTypeCommit:
		content.commit.marshal(b)
	default:
		panic("unreachable")
	}
	content.auth.marshal(b, ct)
}

func (content *privateMessageContent) authenticatedContent(framedContent *framedContent) *authenticatedContent {
	return &authenticatedContent{
		wireFormat: wireFormatMLSPrivateMessage,
		content:    *framedContent,
		auth:       content.auth,
	}
}

func signPrivateMessageContent(cs CipherSuite, signKey signaturePrivateKey, content *framedContent, ctx *groupContext) (*privateMessageContent, error) {
	authContent, err := signAuthenticatedContent(cs, signKey, wireFormatMLSPrivateMessage, content, ctx)
	if err != nil {
		return nil, err
	}

	return &privateMessageContent{
		applicationData: content.applicationData,
		proposal:        content.proposal,
		commit:          content.commit,
		auth:            authContent.auth,
	}, nil
}

func encryptPrivateMessageContent(cs CipherSuite, secret ratchetSecret, content *framedContent, privContent *privateMessageContent, reuseGuard [4]byte) ([]byte, error) {
	var b cryptobyte.Builder
	privContent.marshal(&b, content.contentType)
	plaintext, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	key, nonce, err := derivePrivateMessageKeyAndNonce(cs, secret, reuseGuard)
	if err != nil {
		return nil, err
	}

	aad := privateContentAAD{
		groupID:           content.groupID,
		epoch:             content.epoch,
		contentType:       content.contentType,
		authenticatedData: content.authenticatedData,
	}
	rawAAD, err := marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	return cipher.Seal(nil, nonce, plaintext, rawAAD), nil
}

func encryptSenderData(cs CipherSuite, senderDataSecret []byte, senderData *senderData, content *framedContent, ciphertext []byte) ([]byte, error) {
	key, err := expandSenderDataKey(cs, senderDataSecret, ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := expandSenderDataNonce(cs, senderDataSecret, ciphertext)
	if err != nil {
		return nil, err
	}

	aad := senderDataAAD{
		groupID:     content.groupID,
		epoch:       content.epoch,
		contentType: content.contentType,
	}
	rawAAD, err := marshal(&aad)
	if err != nil {
		return nil, err
	}

	_, _, aead := cs.hpke().Params()
	cipher, err := aead.New(key)
	if err != nil {
		return nil, err
	}

	rawSenderData, err := marshal(senderData)
	if err != nil {
		return nil, err
	}

	return cipher.Seal(nil, nonce, rawSenderData, rawAAD), nil
}

type senderData struct {
	leafIndex  leafIndex
	generation uint32
	reuseGuard [4]byte
}

func newSenderData(leafIndex leafIndex, generation uint32) (*senderData, error) {
	data := senderData{
		leafIndex:  leafIndex,
		generation: generation,
	}
	if _, err := rand.Read(data.reuseGuard[:]); err != nil {
		return nil, err
	}
	return &data, nil
}

func (data *senderData) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint32((*uint32)(&data.leafIndex)) || !s.ReadUint32(&data.generation) || !s.CopyBytes(data.reuseGuard[:]) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (data *senderData) marshal(b *cryptobyte.Builder) {
	b.AddUint32(uint32(data.leafIndex))
	b.AddUint32(data.generation)
	b.AddBytes(data.reuseGuard[:])
}

func expandSenderDataKey(cs CipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.expandWithLabel(senderDataSecret, []byte("key"), ciphertextSample, uint16(aead.KeySize()))
}

func expandSenderDataNonce(cs CipherSuite, senderDataSecret, ciphertext []byte) ([]byte, error) {
	_, _, aead := cs.hpke().Params()
	ciphertextSample := sampleCiphertext(cs, ciphertext)
	return cs.expandWithLabel(senderDataSecret, []byte("nonce"), ciphertextSample, uint16(aead.NonceSize()))
}

func sampleCiphertext(cs CipherSuite, ciphertext []byte) []byte {
	_, kdf, _ := cs.hpke().Params()
	n := kdf.ExtractSize()
	if len(ciphertext) < n {
		return ciphertext
	}
	return ciphertext[:n]
}
