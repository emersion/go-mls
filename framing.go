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

type senderType uint8

const (
	senderTypeMember            senderType = 1
	senderTypeExternal          senderType = 2
	senderTypeNewMemberProposal senderType = 3
	senderTypeNewMemberCommit   senderType = 4
)

type sender struct {
	senderType  senderType
	leafIndex   uint32 // for senderTypeMember
	senderIndex uint32 // for senderTypeExternal
}

func unmarshalSender(s *cryptobyte.String) (*sender, error) {
	var sender sender
	if !s.ReadUint8((*uint8)(&sender.senderType)) {
		return nil, io.ErrUnexpectedEOF
	}
	switch sender.senderType {
	case senderTypeMember:
		if !s.ReadUint32(&sender.leafIndex) {
			return nil, io.ErrUnexpectedEOF
		}
	case senderTypeExternal:
		if !s.ReadUint32(&sender.senderIndex) {
			return nil, io.ErrUnexpectedEOF
		}
	case senderTypeNewMemberProposal, senderTypeNewMemberCommit:
		// nothing to do
	default:
		return nil, fmt.Errorf("mls: invalid sender type %d", sender.senderType)
	}
	return &sender, nil
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

func unmarshalFramedContent(s *cryptobyte.String) (*framedContent, error) {
	var framedContent framedContent
	if !readOpaqueVec(s, (*[]byte)(&framedContent.groupID)) || !s.ReadUint64(&framedContent.epoch) {
		return nil, io.ErrUnexpectedEOF
	}

	sender, err := unmarshalSender(s)
	if err != nil {
		return nil, err
	}
	framedContent.sender = *sender

	if !readOpaqueVec(s, &framedContent.authenticatedData) || !s.ReadUint8((*uint8)(&framedContent.contentType)) {
		return nil, io.ErrUnexpectedEOF
	}

	switch framedContent.contentType {
	case contentTypeApplication:
		if !readOpaqueVec(s, &framedContent.applicationData) {
			return nil, io.ErrUnexpectedEOF
		}
	case contentTypeProposal:
		return nil, fmt.Errorf("TODO: unmarshalFramedContent")
	case contentTypeCommit:
		return nil, fmt.Errorf("TODO: unmarshalFramedContent")
	default:
		return nil, fmt.Errorf("mls: invalid content type %d", framedContent.contentType)
	}

	return &framedContent, nil
}

type mlsMessage struct {
	version        protocolVersion
	wireFormat     wireFormat
	publicMessage  *publicMessage
	privateMessage *privateMessage
	welcome        *welcome
	groupInfo      *groupInfo
	keyPackage     *keyPackage
}

func unmarshalMLSMessage(s *cryptobyte.String) (*mlsMessage, error) {
	var msg mlsMessage
	if !s.ReadUint16((*uint16)(&msg.version)) || !s.ReadUint16((*uint16)(&msg.wireFormat)) {
		return nil, io.ErrUnexpectedEOF
	}

	if msg.version != protocolVersionMLS10 {
		return nil, fmt.Errorf("mls: invalid protocol version %d", msg.version)
	}

	var err error
	switch msg.wireFormat {
	case wireFormatMLSPublicMessage:
		msg.publicMessage, err = unmarshalPublicMessage(s)
	case wireFormatMLSPrivateMessage:
		msg.privateMessage, err = unmarshalPrivateMessage(s)
	case wireFormatMLSWelcome:
		msg.welcome, err = unmarshalWelcome(s)
	case wireFormatMLSGroupInfo:
		msg.groupInfo, err = unmarshalGroupInfo(s)
	case wireFormatMLSKeyPackage:
		msg.keyPackage, err = unmarshalKeyPackage(s)
	default:
		err = fmt.Errorf("mls: invalid wire format %d", msg.wireFormat)
	}
	if err != nil {
		return nil, err
	}

	return &msg, nil
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

func unmarshalFramedContentAuthData(s *cryptobyte.String, ct contentType) (*framedContentAuthData, error) {
	var authData framedContentAuthData
	if !readOpaqueVec(s, &authData.signature) {
		return nil, io.ErrUnexpectedEOF
	}

	if ct == contentTypeCommit {
		if !readOpaqueVec(s, &authData.confirmationTag) {
			return nil, io.ErrUnexpectedEOF
		}
	}

	return &authData, nil
}

type publicMessage struct {
	content       framedContent
	auth          framedContentAuthData
	membershipTag []byte // for senderTypeMember
}

func unmarshalPublicMessage(s *cryptobyte.String) (*publicMessage, error) {
	content, err := unmarshalFramedContent(s)
	if err != nil {
		return nil, err
	}

	auth, err := unmarshalFramedContentAuthData(s, content.contentType)
	if err != nil {
		return nil, err
	}

	msg := publicMessage{
		content: *content,
		auth:    *auth,
	}
	if content.sender.senderType == senderTypeMember {
		if !readOpaqueVec(s, &msg.membershipTag) {
			return nil, io.ErrUnexpectedEOF
		}
	}

	return &msg, nil
}

type privateMessage struct {
	groupID             GroupID
	epoch               uint64
	contentType         contentType
	authenticatedData   []byte
	encryptedSenderData []byte
	ciphertext          []byte
}

func unmarshalPrivateMessage(s *cryptobyte.String) (*privateMessage, error) {
	var msg privateMessage
	if !readOpaqueVec(s, (*[]byte)(&msg.groupID)) || !s.ReadUint64(&msg.epoch) || !s.ReadUint8((*uint8)(&msg.contentType)) {
		return nil, io.ErrUnexpectedEOF
	}
	if !readOpaqueVec(s, &msg.authenticatedData) || !readOpaqueVec(s, &msg.encryptedSenderData) || !readOpaqueVec(s, &msg.ciphertext) {
		return nil, io.ErrUnexpectedEOF
	}
	return &msg, nil
}

type privateMessageContent struct {
	applicationData []byte    // for contentTypeApplication
	proposal        *proposal // for contentTypeProposal
	commit          *commit   // for contentTypeCommit

	auth framedContentAuthData
}

type senderData struct {
	leafIndex  uint32
	generation uint32
	reuseGuard [4]byte
}
