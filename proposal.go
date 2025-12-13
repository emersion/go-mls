package mls

import (
	"bytes"
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

func (t proposalType) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(t))
}

type proposal struct {
	proposalType           proposalType
	add                    *add                    // for proposalTypeAdd
	update                 *update                 // for proposalTypeUpdate
	remove                 *remove                 // for proposalTypeRemove
	preSharedKey           *preSharedKey           // for proposalTypePSK
	reInit                 *reInit                 // for proposalTypeReinit
	externalInit           *externalInit           // for proposalTypeExternalInit
	groupContextExtensions *groupContextExtensions // for proposalTypeGroupContextExtensions
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
	case proposalTypeUpdate:
		prop.update = new(update)
		return prop.update.unmarshal(s)
	case proposalTypeRemove:
		prop.remove = new(remove)
		return prop.remove.unmarshal(s)
	case proposalTypePSK:
		prop.preSharedKey = new(preSharedKey)
		return prop.preSharedKey.unmarshal(s)
	case proposalTypeReinit:
		prop.reInit = new(reInit)
		return prop.reInit.unmarshal(s)
	case proposalTypeExternalInit:
		prop.externalInit = new(externalInit)
		return prop.externalInit.unmarshal(s)
	case proposalTypeGroupContextExtensions:
		prop.groupContextExtensions = new(groupContextExtensions)
		return prop.groupContextExtensions.unmarshal(s)
	default:
		panic("unreachable")
	}
}

func (prop *proposal) marshal(b *cryptobyte.Builder) {
	prop.proposalType.marshal(b)
	switch prop.proposalType {
	case proposalTypeAdd:
		prop.add.marshal(b)
	case proposalTypeUpdate:
		prop.update.marshal(b)
	case proposalTypeRemove:
		prop.remove.marshal(b)
	case proposalTypePSK:
		prop.preSharedKey.marshal(b)
	case proposalTypeReinit:
		prop.reInit.marshal(b)
	case proposalTypeExternalInit:
		prop.externalInit.marshal(b)
	case proposalTypeGroupContextExtensions:
		prop.groupContextExtensions.marshal(b)
	default:
		panic("unreachable")
	}
}

type add struct {
	keyPackage KeyPackage
}

func (a *add) unmarshal(s *cryptobyte.String) error {
	*a = add{}
	return a.keyPackage.unmarshal(s)
}

func (a *add) marshal(b *cryptobyte.Builder) {
	a.keyPackage.marshal(b)
}

type update struct {
	leafNode leafNode
}

func (upd *update) unmarshal(s *cryptobyte.String) error {
	*upd = update{}
	return upd.leafNode.unmarshal(s)
}

func (upd *update) marshal(b *cryptobyte.Builder) {
	upd.leafNode.marshal(b)
}

type remove struct {
	removed leafIndex
}

func (rm *remove) unmarshal(s *cryptobyte.String) error {
	*rm = remove{}
	if !s.ReadUint32((*uint32)(&rm.removed)) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (rm *remove) marshal(b *cryptobyte.Builder) {
	b.AddUint32(uint32(rm.removed))
}

type preSharedKey struct {
	psk preSharedKeyID
}

func (psk *preSharedKey) unmarshal(s *cryptobyte.String) error {
	*psk = preSharedKey{}
	return psk.psk.unmarshal(s)
}

func (psk *preSharedKey) marshal(b *cryptobyte.Builder) {
	psk.psk.marshal(b)
}

type reInit struct {
	groupID     GroupID
	version     protocolVersion
	cipherSuite CipherSuite
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

func (ri *reInit) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(ri.groupID))
	b.AddUint16(uint16(ri.version))
	b.AddUint16(uint16(ri.cipherSuite))
	marshalExtensionVec(b, ri.extensions)
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

func (ei *externalInit) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, ei.kemOutput)
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

func (exts *groupContextExtensions) marshal(b *cryptobyte.Builder) {
	marshalExtensionVec(b, exts.extensions)
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

func (t proposalOrRefType) marshal(b *cryptobyte.Builder) {
	b.AddUint8(uint8(t))
}

type proposalRef []byte

func (ref proposalRef) Equal(other proposalRef) bool {
	return bytes.Equal([]byte(ref), []byte(other))
}

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

func (propOrRef *proposalOrRef) marshal(b *cryptobyte.Builder) {
	propOrRef.typ.marshal(b)
	switch propOrRef.typ {
	case proposalOrRefTypeProposal:
		propOrRef.proposal.marshal(b)
	case proposalOrRefTypeReference:
		writeOpaqueVec(b, []byte(propOrRef.reference))
	default:
		panic("unreachable")
	}
}

// verifyProposalList ensures that a list of proposals passes the checks for a
// regular commit described in section 12.2.
//
// It does not perform all checks:
//
//   - It does not check the validity of individual proposals (section 12.1).
//   - It does not check whether members in add proposals are already part of
//     the group.
//   - It does not check whether non-default proposal types are supported by
//     all members of the group who will process the commit.
//   - It does not check whether the ratchet tree is valid after processing the
//     commit.
func verifyProposalList(proposals []proposal, senders []leafIndex, committer leafIndex) error {
	if len(proposals) != len(senders) {
		panic("unreachable")
	}

	add := make(map[string]struct{})
	updateOrRemove := make(map[leafIndex]struct{})
	psk := make(map[string]struct{})
	groupContextExtensions := false
	for i, prop := range proposals {
		sender := senders[i]

		switch prop.proposalType {
		case proposalTypeAdd:
			k := string(prop.add.keyPackage.leafNode.signatureKey)
			if _, dup := add[k]; dup {
				return fmt.Errorf("mls: multiple add proposals have the same signature key")
			}
			add[k] = struct{}{}
		case proposalTypeUpdate:
			if sender == committer {
				return fmt.Errorf("mls: update proposal generated by the committer")
			}
			if _, dup := updateOrRemove[sender]; dup {
				return fmt.Errorf("mls: multiple update and/or remove proposals apply to the same leaf")
			}
			updateOrRemove[sender] = struct{}{}
		case proposalTypeRemove:
			if prop.remove.removed == committer {
				return fmt.Errorf("mls: remove proposal removes the committer")
			}
			if _, dup := updateOrRemove[prop.remove.removed]; dup {
				return fmt.Errorf("mls: multiple update and/or remove proposals apply to the same leaf")
			}
			updateOrRemove[prop.remove.removed] = struct{}{}
		case proposalTypePSK:
			b, err := marshal(&prop.preSharedKey.psk)
			if err != nil {
				return err
			}
			k := string(b)
			if _, dup := psk[k]; dup {
				return fmt.Errorf("mls: multiple PSK proposals reference the same PSK ID")
			}
			psk[k] = struct{}{}
		case proposalTypeGroupContextExtensions:
			if groupContextExtensions {
				return fmt.Errorf("mls: multiple group context extensions proposals")
			}
			groupContextExtensions = true
		case proposalTypeReinit:
			if len(proposals) > 1 {
				return fmt.Errorf("mls: reinit proposal together with any other proposal")
			}
		case proposalTypeExternalInit:
			return fmt.Errorf("mls: external init proposal is not allowed")
		}
	}
	return nil
}

func proposalListNeedsPath(proposals []proposal) bool {
	if len(proposals) == 0 {
		return true
	}

	for _, prop := range proposals {
		switch prop.proposalType {
		case proposalTypeUpdate, proposalTypeRemove, proposalTypeExternalInit, proposalTypeGroupContextExtensions:
			return true
		}
	}

	return false
}
