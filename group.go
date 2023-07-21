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
	// TODO: extensions
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
	// TODO
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

	ss, ok := vectorString(s)
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	for !ss.Empty() {
		sec, err := unmarshalEncryptedGroupSecrets(&ss)
		if err != nil {
			return nil, err
		}
		welcome.secrets = append(welcome.secrets, *sec)
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
