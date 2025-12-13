package mls

import (
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// A Group is a high-level API for an MLS group.
type Group struct {
	tree         ratchetTree
	groupContext groupContext

	interimTranscriptHash []byte
	pskSecret             []byte
	epochSecret           []byte
	initSecret            []byte
}

// GroupFromWelcome creates a new group from a welcome message.
func GroupFromWelcome(welcome *Welcome, keyPkgRef KeyPackageRef, initKeyPriv []byte) (*Group, error) {
	groupSecrets, err := welcome.decryptGroupSecrets(keyPkgRef, initKeyPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt group secrets: %v", err)
	}

	if !groupSecrets.verifySingleReinitOrBranchPSK() {
		return nil, fmt.Errorf("mls: more than one key has usage reinit or branch in group secrets")
	}

	if len(groupSecrets.psks) != 0 {
		return nil, fmt.Errorf("mls: group secret PSKs are not yet supported")
	}

	group, _, err := groupFromSecrets(welcome, groupSecrets, nil)
	return group, err
}

type groupFromSecretsOptions struct {
	rawTree []byte
	psks    [][]byte
	now     func() time.Time
}

func groupFromSecrets(welcome *Welcome, groupSecrets *groupSecrets, options *groupFromSecretsOptions) (*Group, *groupInfo, error) {
	if options == nil {
		options = new(groupFromSecretsOptions)
	}

	pskSecret, err := extractPSKSecret(welcome.cipherSuite, groupSecrets.psks, options.psks)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract PSK secret: %v", err)
	}

	groupInfo, err := welcome.decryptGroupInfo(groupSecrets.joinerSecret, pskSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt group info: %v", err)
	}

	rawTree := options.rawTree
	if rawTree == nil {
		rawTree = findExtensionData(groupInfo.extensions, extensionTypeRatchetTree)
	}
	if rawTree == nil {
		return nil, nil, fmt.Errorf("mls: missing ratchet tree")
	}

	var tree ratchetTree
	if err := unmarshal(rawTree, &tree); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal ratchet tree: %v", err)
	}

	signerNode := tree.getLeaf(groupInfo.signer)
	if signerNode == nil {
		return nil, nil, fmt.Errorf("mls: signer node is blank")
	} else if !groupInfo.verifySignature(signerNode.signatureKey) {
		return nil, nil, fmt.Errorf("mls: failed to verify signer node signature")
	}
	if !groupInfo.verifyConfirmationTag(groupSecrets.joinerSecret, pskSecret) {
		return nil, nil, fmt.Errorf("mls: failed to verify confirmation tag")
	}
	if groupInfo.groupContext.cipherSuite != welcome.cipherSuite {
		return nil, nil, fmt.Errorf("mls: group info cipher suite doesn't match key package")
	}

	if err := tree.verifyIntegrity(&groupInfo.groupContext, options.now); err != nil {
		return nil, nil, fmt.Errorf("failed to verify ratchet tree integrity: %v", err)
	}

	// TODO: perform other group info verification steps

	groupCtx := groupInfo.groupContext

	epochSecret, err := groupCtx.extractEpochSecret(groupSecrets.joinerSecret, pskSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract epoch secret: %v", err)
	}

	initSecret, err := groupCtx.cipherSuite.deriveSecret(epochSecret, secretLabelInit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive init secret: %v", err)
	}

	interimTranscriptHash, err := nextInterimTranscriptHash(groupCtx.cipherSuite, groupCtx.confirmedTranscriptHash, groupInfo.confirmationTag)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute next interim transcript hash: %v", err)
	}

	return &Group{
		tree:                  tree,
		groupContext:          groupCtx,
		interimTranscriptHash: interimTranscriptHash,
		pskSecret:             pskSecret,
		epochSecret:           epochSecret,
		initSecret:            initSecret,
	}, groupInfo, nil
}

func (group *Group) verifyPublicMessage(pubMsg *publicMessage) (*authenticatedContent, error) {
	if !pubMsg.content.groupID.Equal(group.groupContext.groupID) {
		return nil, fmt.Errorf("mls: message group ID mismatch")
	}
	if pubMsg.content.epoch != group.groupContext.epoch {
		return nil, fmt.Errorf("mls: epoch mismatch: got %v, want %v", pubMsg.content.epoch, group.groupContext.epoch)
	}

	if pubMsg.content.sender.senderType != senderTypeMember {
		// TODO: support other sender types
		return nil, fmt.Errorf("mls: unsupported sender type: %v", pubMsg.content.sender.senderType)
	}
	senderLeafIndex := pubMsg.content.sender.leafIndex
	// TODO: check tree length
	senderNode := group.tree.getLeaf(senderLeafIndex)
	if senderNode == nil {
		return nil, fmt.Errorf("mls: blank leaf node for sender")
	}

	authContent := pubMsg.authenticatedContent()
	if !authContent.verifySignature([]byte(senderNode.signatureKey), &group.groupContext) {
		return nil, fmt.Errorf("mls: failed to verify public message signature")
	}

	membershipKey, err := group.groupContext.cipherSuite.deriveSecret(group.epochSecret, secretLabelMembership)
	if err != nil {
		return nil, fmt.Errorf("failed to derive membership key: %v", err)
	} else if !pubMsg.verifyMembershipTag(membershipKey, &group.groupContext) {
		return nil, fmt.Errorf("failed to verify membership tag")
	}

	return authContent, nil
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
