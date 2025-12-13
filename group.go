package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

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

// A Welcome message includes secret keying information necessary to join a
// group.
type Welcome struct {
	cipherSuite        CipherSuite
	secrets            []encryptedGroupSecrets
	encryptedGroupInfo []byte
}

// UnmarshalWelcome reads a welcome message.
func UnmarshalWelcome(raw []byte) (*Welcome, error) {
	var msg mlsMessage
	if err := unmarshal(raw, &msg); err != nil {
		return nil, err
	} else if msg.wireFormat != wireFormatMLSWelcome {
		return nil, fmt.Errorf("mls: expected a key package message, got wire format %v", msg.wireFormat)
	}
	return msg.welcome, nil
}

func (w *Welcome) unmarshal(s *cryptobyte.String) error {
	*w = Welcome{}

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

func (w *Welcome) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(w.cipherSuite))
	writeVector(b, len(w.secrets), func(b *cryptobyte.Builder, i int) {
		w.secrets[i].marshal(b)
	})
	writeOpaqueVec(b, w.encryptedGroupInfo)
}

// NewMembers returns the list of key package references this welcome message
// contains secret keying information for.
func (w *Welcome) NewMembers() []KeyPackageRef {
	refs := make([]KeyPackageRef, len(w.secrets))
	for i, sec := range w.secrets {
		refs[i] = sec.newMember
	}
	return refs
}

func (w *Welcome) findSecret(ref KeyPackageRef) *encryptedGroupSecrets {
	for i, sec := range w.secrets {
		if sec.newMember.Equal(ref) {
			return &w.secrets[i]
		}
	}
	return nil
}

func (w *Welcome) decryptGroupSecrets(ref KeyPackageRef, initKeyPriv []byte) (*groupSecrets, error) {
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

func (w *Welcome) decryptGroupInfo(joinerSecret, pskSecret []byte) (*groupInfo, error) {
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
	newMember             KeyPackageRef
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
