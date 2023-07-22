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

func (t *proposalType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint16((*uint16)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case proposalTypeAdd, proposalTypeUpdate, proposalTypeRemove, proposalTypePSK, proposalTypeReinit, proposalTypeExternalInit, proposalTypeGroupContextExtensions:
		return nil
	default:
		return fmt.Errorf("mls: invalid proposal type %d", *t)
	}
}

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

func (prop *proposal) unmarshal(s *cryptobyte.String) error {
	*prop = proposal{}
	if err := prop.proposalType.unmarshal(s); err != nil {
		return err
	}
	switch prop.proposalType {
	case proposalTypeAdd:
		prop.add = new(add)
		return prop.add.unmarshal(s)
	case proposalTypeUpdate, proposalTypeRemove, proposalTypePSK, proposalTypeReinit, proposalTypeExternalInit, proposalTypeGroupContextExtensions:
		return fmt.Errorf("TODO: proposal.unmarshal(%v)", prop.proposalType)
	default:
		panic("unreachable")
	}
}

type add struct {
	keyPackage keyPackage
}

func (a *add) unmarshal(s *cryptobyte.String) error {
	*a = add{}
	return a.keyPackage.unmarshal(s)
}

type update struct {
	leafNode leafNode
}

func (upd *update) unmarshal(s *cryptobyte.String) error {
	*upd = update{}
	return upd.leafNode.unmarshal(s)
}

type remove struct {
	removed uint32
}

func (rm *remove) unmarshal(s *cryptobyte.String) error {
	*rm = remove{}
	if !s.ReadUint32(&rm.removed) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

type preSharedKey struct {
	psk preSharedKeyID
}

func (psk *preSharedKey) unmarshal(s *cryptobyte.String) error {
	*psk = preSharedKey{}
	return psk.psk.unmarshal(s)
}

type reInit struct {
	groupID     GroupID
	version     protocolVersion
	cipherSuite cipherSuite
	extensions  []extension
}

func (ri *reInit) unmarshal(s *cryptobyte.String) error {
	*ri = reInit{}

	if !readOpaqueVec(s, (*[]byte)(&ri.groupID)) || !s.ReadUint16((*uint16)(&ri.version)) || !s.ReadUint16((*uint16)(&ri.cipherSuite)) {
		return io.ErrUnexpectedEOF
	}

	exts, err := unmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	ri.extensions = exts

	return nil
}

type externalInit struct {
	kemOutput []byte
}

func (ei *externalInit) unmarshal(s *cryptobyte.String) error {
	*ei = externalInit{}
	if !readOpaqueVec(s, &ei.kemOutput) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

type groupContextExtensions struct {
	extensions []extension
}

func (exts *groupContextExtensions) unmarshal(s *cryptobyte.String) error {
	*exts = groupContextExtensions{}

	l, err := unmarshalExtensionVec(s)
	if err != nil {
		return err
	}
	exts.extensions = l

	return nil
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

type proposalRef []byte

type proposalOrRef struct {
	typ       proposalOrRefType
	proposal  *proposal   // for proposalOrRefTypeProposal
	reference proposalRef // for proposalOrRefTypeReference
}

func (propOrRef *proposalOrRef) unmarshal(s *cryptobyte.String) error {
	*propOrRef = proposalOrRef{}

	if err := propOrRef.typ.unmarshal(s); err != nil {
		return err
	}

	switch propOrRef.typ {
	case proposalOrRefTypeProposal:
		propOrRef.proposal = new(proposal)
		return propOrRef.proposal.unmarshal(s)
	case proposalOrRefTypeReference:
		if !readOpaqueVec(s, (*[]byte)(&propOrRef.reference)) {
			return io.ErrUnexpectedEOF
		}
		return nil
	default:
		panic("unreachable")
	}
}

type commit struct {
	proposals []proposalOrRef
	path      *updatePath // optional
}

func (c *commit) unmarshal(s *cryptobyte.String) error {
	*c = commit{}

	err := readVector(s, func(s *cryptobyte.String) error {
		var propOrRef proposalOrRef
		if err := propOrRef.unmarshal(s); err != nil {
			return err
		}
		c.proposals = append(c.proposals, propOrRef)
		return nil
	})
	if err != nil {
		return err
	}

	var hasPath bool
	if !readOptional(s, &hasPath) {
		return io.ErrUnexpectedEOF
	} else if hasPath {
		c.path = new(updatePath)
		if err := c.path.unmarshal(s); err != nil {
			return err
		}
	}

	return nil
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

type groupSecrets struct {
	joinerSecret []byte
	pathSecret   []byte // optional
	psks         []preSharedKeyID
}

func (sec *groupSecrets) unmarshal(s *cryptobyte.String) error {
	*sec = groupSecrets{}

	if !readOpaqueVec(s, &sec.joinerSecret) {
		return io.ErrUnexpectedEOF
	}

	var hasPathSecret bool
	if !readOptional(s, &hasPathSecret) {
		return io.ErrUnexpectedEOF
	} else if hasPathSecret && !readOpaqueVec(s, &sec.pathSecret) {
		return io.ErrUnexpectedEOF
	}

	return readVector(s, func(s *cryptobyte.String) error {
		var psk preSharedKeyID
		if err := psk.unmarshal(s); err != nil {
			return err
		}
		sec.psks = append(sec.psks, psk)
		return nil
	})
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
