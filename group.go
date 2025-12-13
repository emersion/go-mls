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
	keyPackage keyPackage
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

func (c *commit) marshal(b *cryptobyte.Builder) {
	writeVector(b, len(c.proposals), func(b *cryptobyte.Builder, i int) {
		c.proposals[i].marshal(b)
	})
	writeOptional(b, c.path != nil)
	if c.path != nil {
		c.path.marshal(b)
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

type groupInfo struct {
	groupContext    groupContext
	extensions      []extension
	confirmationTag []byte
	signer          leafIndex
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

	if !readOpaqueVec(s, &info.confirmationTag) || !s.ReadUint32((*uint32)(&info.signer)) || !readOpaqueVec(s, &info.signature) {
		return err
	}

	return nil
}

func (info *groupInfo) marshal(b *cryptobyte.Builder) {
	(*groupInfoTBS)(info).marshal(b)
	writeOpaqueVec(b, info.signature)
}

func (info *groupInfo) verifySignature(signerPub signaturePublicKey) bool {
	cs := info.groupContext.cipherSuite
	tbs, err := marshal((*groupInfoTBS)(info))
	if err != nil {
		return false
	}
	return cs.verifyWithLabel([]byte(signerPub), []byte("GroupInfoTBS"), tbs, info.signature)
}

func (info *groupInfo) verifyConfirmationTag(joinerSecret, pskSecret []byte) bool {
	cs := info.groupContext.cipherSuite
	epochSecret, err := info.groupContext.extractEpochSecret(joinerSecret, pskSecret)
	if err != nil {
		return false
	}
	confirmationKey, err := cs.deriveSecret(epochSecret, secretLabelConfirm)
	if err != nil {
		return false
	}
	return cs.verifyMAC(confirmationKey, info.groupContext.confirmedTranscriptHash, info.confirmationTag)
}

type groupInfoTBS groupInfo

func (info *groupInfoTBS) marshal(b *cryptobyte.Builder) {
	info.groupContext.marshal(b)
	marshalExtensionVec(b, info.extensions)
	writeOpaqueVec(b, info.confirmationTag)
	b.AddUint32(uint32(info.signer))
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

func (sec *groupSecrets) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, sec.joinerSecret)

	writeOptional(b, sec.pathSecret != nil)
	if sec.pathSecret != nil {
		writeOpaqueVec(b, sec.pathSecret)
	}

	writeVector(b, len(sec.psks), func(b *cryptobyte.Builder, i int) {
		sec.psks[i].marshal(b)
	})
}

// verifySingleReInitOrBranchPSK verifies that at most one key has type
// resumption with usage reinit or branch.
func (sec *groupSecrets) verifySingleReinitOrBranchPSK() bool {
	n := 0
	for _, pskID := range sec.psks {
		if pskID.pskType != pskTypeResumption {
			continue
		}
		switch pskID.usage {
		case resumptionPSKUsageReinit, resumptionPSKUsageBranch:
			n++
		}
	}
	return n <= 1
}

type welcome struct {
	cipherSuite        CipherSuite
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

func (w *welcome) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(w.cipherSuite))
	writeVector(b, len(w.secrets), func(b *cryptobyte.Builder, i int) {
		w.secrets[i].marshal(b)
	})
	writeOpaqueVec(b, w.encryptedGroupInfo)
}

func (w *welcome) findSecret(ref keyPackageRef) *encryptedGroupSecrets {
	for i, sec := range w.secrets {
		if sec.newMember.Equal(ref) {
			return &w.secrets[i]
		}
	}
	return nil
}

func (w *welcome) decryptGroupSecrets(ref keyPackageRef, initKeyPriv []byte) (*groupSecrets, error) {
	cs := w.cipherSuite

	sec := w.findSecret(ref)
	if sec == nil {
		return nil, fmt.Errorf("mls: encrypted group secrets not found for provided key package ref")
	}

	rawGroupSecrets, err := cs.decryptWithLabel(initKeyPriv, []byte("Welcome"), w.encryptedGroupInfo, sec.encryptedGroupSecrets.kemOutput, sec.encryptedGroupSecrets.ciphertext)
	if err != nil {
		return nil, err
	}
	var groupSecrets groupSecrets
	if err := unmarshal(rawGroupSecrets, &groupSecrets); err != nil {
		return nil, err
	}

	return &groupSecrets, err
}

func (w *welcome) decryptGroupInfo(joinerSecret, pskSecret []byte) (*groupInfo, error) {
	cs := w.cipherSuite
	_, _, aead := cs.hpke().Params()

	welcomeSecret, err := extractWelcomeSecret(cs, joinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}

	welcomeNonce, err := cs.expandWithLabel(welcomeSecret, []byte("nonce"), nil, uint16(aead.NonceSize()))
	if err != nil {
		return nil, err
	}
	welcomeKey, err := cs.expandWithLabel(welcomeSecret, []byte("key"), nil, uint16(aead.KeySize()))
	if err != nil {
		return nil, err
	}

	welcomeCipher, err := aead.New(welcomeKey)
	if err != nil {
		return nil, err
	}
	rawGroupInfo, err := welcomeCipher.Open(nil, welcomeNonce, w.encryptedGroupInfo, nil)
	if err != nil {
		return nil, err
	}

	var groupInfo groupInfo
	if err := unmarshal(rawGroupInfo, &groupInfo); err != nil {
		return nil, err
	}

	return &groupInfo, nil
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

func (sec *encryptedGroupSecrets) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, []byte(sec.newMember))
	sec.encryptedGroupSecrets.marshal(b)
}
