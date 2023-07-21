package mls

import (
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// http://www.iana.org/assignments/mls/mls.xhtml#mls-proposal-types
type proposalType uint16

const (
	proposalTypeAdd                    proposalType = 0x0001
	proposalTypeUpdate                 proposalType = 0x0002
	proposalTypeRemove                 proposalType = 0x0003
	proposalTypePSK                    proposalType = 0x0004
	proposalTypeReinit                 proposalType = 0x0005
	proposalTypeExternalInit           proposalType = 0x0006
	proposalTypeGroupContextExtensions proposalType = 0x0007
)

type proposal struct {
	proposalType           proposalType
	add                    *add
	update                 *update
	remove                 *remove
	preSharedKey           *preSharedKey
	reInit                 *reInit
	externalInit           *externalInit
	groupContextExtensions *groupContextExtensions
}

type add struct {
	keyPackage *keyPackage
}

type update struct {
	// TODO
}

type remove struct {
	removed uint32
}

type preSharedKey struct {
	// TODO
}

type reInit struct {
	groupID     GroupID
	version     protocolVersion
	cipherSuite cipherSuite
	extensions  []extension
}

type externalInit struct {
	kemOutput []byte
}

type groupContextExtensions struct {
	// TODO
}

type proposalOrRefType uint8

const (
	proposalOrRefTypeProposal  proposalOrRefType = 1
	proposalOrRefTypeReference proposalOrRefType = 2
)

type proposalOrRef struct {
	typ      proposalOrRefType
	proposal *proposal
	//reference *reference
}

type commit struct {
	proposals []proposalOrRef
	// TODO: path
}

type groupInfo struct {
	groupContext    groupContext
	extensions      []extension
	confirmationTag []byte
	signer          uint32
	signature       []byte
}

func unmarshalGroupInfo(s *cryptobyte.String) (*groupInfo, error) {
	var info groupInfo

	ctx, err := unmarshalGroupContext(s)
	if err != nil {
		return nil, err
	}
	info.groupContext = *ctx

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return nil, err
	}
	info.extensions = exts

	if !readOpaque(s, &info.confirmationTag) || !s.ReadUint32(&info.signer) || !readOpaque(s, &info.signature) {
		return nil, err
	}

	return &info, nil
}

type groupContext struct {
	version                 protocolVersion
	cipherSuite             cipherSuite
	groupID                 GroupID
	epoch                   uint64
	treeHash                []byte
	confirmedTranscriptHash []byte
	extensions              []extension
}

func unmarshalGroupContext(s *cryptobyte.String) (*groupContext, error) {
	var ctx groupContext
	ok := s.ReadUint16((*uint16)(&ctx.version)) &&
		s.ReadUint16((*uint16)(&ctx.cipherSuite)) &&
		readOpaque(s, (*[]byte)(&ctx.groupID)) &&
		s.ReadUint64(&ctx.epoch) &&
		readOpaque(s, &ctx.treeHash) &&
		readOpaque(s, &ctx.confirmedTranscriptHash)
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return nil, err
	}
	ctx.extensions = exts

	return &ctx, nil
}

type welcome struct {
	cipherSuite        cipherSuite
	secrets            []encryptedGroupSecrets
	encryptedGroupInfo []byte
}

func unmarshalWelcome(s *cryptobyte.String) (*welcome, error) {
	var welcome welcome
	if !s.ReadUint16((*uint16)(&welcome.cipherSuite)) {
		return nil, io.ErrUnexpectedEOF
	}

	err := readVector(s, func(s *cryptobyte.String) error {
		sec, err := unmarshalEncryptedGroupSecrets(s)
		if err != nil {
			return err
		}
		welcome.secrets = append(welcome.secrets, *sec)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if !readOpaque(s, &welcome.encryptedGroupInfo) {
		return nil, io.ErrUnexpectedEOF
	}

	return &welcome, nil
}

type encryptedGroupSecrets struct {
	newMember             keyPackageRef
	encryptedGroupSecrets hpkeCiphertext
}

func unmarshalEncryptedGroupSecrets(s *cryptobyte.String) (*encryptedGroupSecrets, error) {
	var sec encryptedGroupSecrets
	if !readOpaque(s, (*[]byte)(&sec.newMember)) {
		return nil, io.ErrUnexpectedEOF
	}
	hpke, err := unmarshalHPKECiphertext(s)
	if err != nil {
		return nil, err
	}
	sec.encryptedGroupSecrets = *hpke
	return &sec, nil
}
