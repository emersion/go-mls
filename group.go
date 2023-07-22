package mls

import (
	"fmt"
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

func (t *proposalOrRefType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case proposalOrRefTypeProposal, proposalOrRefTypeReference:
		return nil
	default:
		return fmt.Errorf("mls: invalid proposal or ref type %d", *t)
	}
}

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

func (info *groupInfo) unmarshal(s *cryptobyte.String) error {
	*info = groupInfo{}

	if err := info.groupContext.unmarshal(s); err != nil {
		return err
	}

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	info.extensions = exts

	if !readOpaqueVec(s, &info.confirmationTag) || !s.ReadUint32(&info.signer) || !readOpaqueVec(s, &info.signature) {
		return err
	}

	return nil
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

func (ctx *groupContext) unmarshal(s *cryptobyte.String) error {
	*ctx = groupContext{}

	ok := s.ReadUint16((*uint16)(&ctx.version)) &&
		s.ReadUint16((*uint16)(&ctx.cipherSuite)) &&
		readOpaqueVec(s, (*[]byte)(&ctx.groupID)) &&
		s.ReadUint64(&ctx.epoch) &&
		readOpaqueVec(s, &ctx.treeHash) &&
		readOpaqueVec(s, &ctx.confirmedTranscriptHash)
	if !ok {
		return io.ErrUnexpectedEOF
	}

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	ctx.extensions = exts

	return nil
}

type welcome struct {
	cipherSuite        cipherSuite
	secrets            []encryptedGroupSecrets
	encryptedGroupInfo []byte
}

func (w *welcome) unmarshal(s *cryptobyte.String) error {
	*w = welcome{}

	if !s.ReadUint16((*uint16)(&w.cipherSuite)) {
		return io.ErrUnexpectedEOF
	}

	err := readVector(s, func(s *cryptobyte.String) error {
		var sec encryptedGroupSecrets
		if err := sec.unmarshal(s); err != nil {
			return err
		}
		w.secrets = append(w.secrets, sec)
		return nil
	})
	if err != nil {
		return err
	}

	if !readOpaqueVec(s, &w.encryptedGroupInfo) {
		return io.ErrUnexpectedEOF
	}

	return nil
}

type encryptedGroupSecrets struct {
	newMember             keyPackageRef
	encryptedGroupSecrets hpkeCiphertext
}

func (sec *encryptedGroupSecrets) unmarshal(s *cryptobyte.String) error {
	*sec = encryptedGroupSecrets{}
	if !readOpaqueVec(s, (*[]byte)(&sec.newMember)) {
		return io.ErrUnexpectedEOF
	}
	if err := sec.encryptedGroupSecrets.unmarshal(s); err != nil {
		return err
	}
	return nil
}
