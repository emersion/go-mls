package mls

import (
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

type pendingProposal struct {
	ref      proposalRef
	proposal *proposal
	sender   leafIndex
}

// A Group is a high-level API for an MLS group.
type Group struct {
	tree         ratchetTree
	groupContext groupContext

	interimTranscriptHash []byte
	pskSecret             []byte
	epochSecret           []byte
	initSecret            []byte

	myLeafIndex   leafIndex
	privTree      [][]byte
	signaturePriv []byte

	pendingProposals []pendingProposal
}

// CreateGroup creates a new group with a single member.
func CreateGroup(groupID GroupID, keyPairPkg *KeyPairPackage) (*Group, error) {
	cs := keyPairPkg.Public.cipherSuite

	tree := make(ratchetTree, 1)
	tree.add(&keyPairPkg.Public.leafNode)

	privTree := make([][]byte, len(tree))
	privTree[0] = keyPairPkg.Private.EncryptionKey

	treeHash, err := tree.computeRootTreeHash(cs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute root tree hash: %v", err)
	}

	confirmedTranscriptHash := make([]byte, cs.hash().Size())

	_, kdf, _ := cs.hpke().Params()
	epochSecret := make([]byte, kdf.ExtractSize())
	if _, err := rand.Read(epochSecret); err != nil {
		return nil, fmt.Errorf("failed to generate epoch secret: %v", err)
	}

	groupCtx := groupContext{
		version:                 keyPairPkg.Public.version,
		cipherSuite:             keyPairPkg.Public.cipherSuite,
		groupID:                 groupID,
		epoch:                   0,
		treeHash:                treeHash,
		confirmedTranscriptHash: confirmedTranscriptHash,
	}

	confirmationTag, err := groupCtx.signConfirmationTag(epochSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign confirmation tag: %v", err)
	}

	interimTranscriptHash, err := nextInterimTranscriptHash(cs, confirmedTranscriptHash, confirmationTag)
	if err != nil {
		return nil, fmt.Errorf("failed to compute initial interim transcript hash: %v", err)
	}

	pskSecret, err := extractPSKSecret(cs, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PSK secret: %v", err)
	}

	initSecret, err := groupCtx.cipherSuite.deriveSecret(epochSecret, secretLabelInit)
	if err != nil {
		return nil, fmt.Errorf("failed to derive init secret: %v", err)
	}

	return &Group{
		tree:                  tree,
		privTree:              privTree,
		myLeafIndex:           0,
		signaturePriv:         keyPairPkg.Private.SignatureKey,
		groupContext:          groupCtx,
		interimTranscriptHash: interimTranscriptHash,
		pskSecret:             pskSecret,
		epochSecret:           epochSecret,
		initSecret:            initSecret,
	}, nil
}

// GroupFromWelcome creates a new group from a welcome message.
func GroupFromWelcome(welcome *Welcome, keyPairPkg *KeyPairPackage) (*Group, error) {
	keyPkgRef, err := keyPairPkg.Public.GenerateRef()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key package ref: %v", err)
	}

	groupSecrets, err := welcome.decryptGroupSecrets(keyPkgRef, keyPairPkg.Private.InitKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt group secrets: %v", err)
	}

	if !groupSecrets.verifySingleReinitOrBranchPSK() {
		return nil, fmt.Errorf("mls: more than one key has usage reinit or branch in group secrets")
	}

	if len(groupSecrets.psks) != 0 {
		return nil, fmt.Errorf("mls: group secret PSKs are not yet supported")
	}

	return groupFromSecrets(welcome, keyPairPkg, groupSecrets, nil)
}

type groupFromSecretsOptions struct {
	rawTree []byte
	psks    [][]byte
	now     func() time.Time
}

func groupFromSecrets(welcome *Welcome, keyPairPkg *KeyPairPackage, groupSecrets *groupSecrets, options *groupFromSecretsOptions) (*Group, error) {
	if options == nil {
		options = new(groupFromSecretsOptions)
	}

	pskSecret, err := extractPSKSecret(welcome.cipherSuite, groupSecrets.psks, options.psks)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PSK secret: %v", err)
	}

	groupInfo, err := welcome.decryptGroupInfo(groupSecrets.joinerSecret, pskSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt group info: %v", err)
	}

	rawTree := options.rawTree
	if rawTree == nil {
		rawTree = findExtensionData(groupInfo.extensions, extensionTypeRatchetTree)
	}
	if rawTree == nil {
		return nil, fmt.Errorf("mls: missing ratchet tree")
	}

	var tree ratchetTree
	if err := unmarshal(rawTree, &tree); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ratchet tree: %v", err)
	}

	signerNode := tree.getLeaf(groupInfo.signer)
	if signerNode == nil {
		return nil, fmt.Errorf("mls: signer node is blank")
	} else if !groupInfo.verifySignature(signerNode.signatureKey) {
		return nil, fmt.Errorf("mls: failed to verify signer node signature")
	}
	if !groupInfo.verifyConfirmationTag(groupSecrets.joinerSecret, pskSecret) {
		return nil, fmt.Errorf("mls: failed to verify confirmation tag")
	}
	if groupInfo.groupContext.cipherSuite != welcome.cipherSuite {
		return nil, fmt.Errorf("mls: group info cipher suite doesn't match key package")
	}

	if err := tree.verifyIntegrity(&groupInfo.groupContext, options.now); err != nil {
		return nil, fmt.Errorf("failed to verify ratchet tree integrity: %v", err)
	}

	// TODO: perform other group info verification steps

	groupCtx := groupInfo.groupContext

	epochSecret, err := groupCtx.extractEpochSecret(groupSecrets.joinerSecret, pskSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to extract epoch secret: %v", err)
	}

	initSecret, err := groupCtx.cipherSuite.deriveSecret(epochSecret, secretLabelInit)
	if err != nil {
		return nil, fmt.Errorf("failed to derive init secret: %v", err)
	}

	interimTranscriptHash, err := nextInterimTranscriptHash(groupCtx.cipherSuite, groupCtx.confirmedTranscriptHash, groupInfo.confirmationTag)
	if err != nil {
		return nil, fmt.Errorf("failed to compute next interim transcript hash: %v", err)
	}

	myLeafIndex, ok := tree.findLeaf(&keyPairPkg.Public.leafNode)
	if !ok {
		return nil, fmt.Errorf("mls: failed to find my leaf node in ratchet tree")
	}

	privTree := make([][]byte, len(tree))
	privTree[int(myLeafIndex.nodeIndex())] = keyPairPkg.Private.EncryptionKey

	if groupSecrets.pathSecret != nil {
		nodeIndex := commonAncestor(myLeafIndex.nodeIndex(), groupInfo.signer.nodeIndex())
		err := processPathSecret(groupCtx.cipherSuite, tree, privTree, groupSecrets.pathSecret, nodeIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to process path secret: %v", err)
		}
	}

	return &Group{
		tree:                  tree,
		groupContext:          groupCtx,
		interimTranscriptHash: interimTranscriptHash,
		pskSecret:             pskSecret,
		epochSecret:           epochSecret,
		initSecret:            initSecret,
		myLeafIndex:           myLeafIndex,
		privTree:              privTree,
		signaturePriv:         keyPairPkg.Private.SignatureKey,
	}, nil
}

func processPathSecret(cs CipherSuite, tree ratchetTree, privTree [][]byte, pathSecret []byte, nodeIndex nodeIndex) error {
	nodePriv, err := nodePrivFromPathSecret(cs, pathSecret, tree.get(nodeIndex).encryptionKey())
	if err != nil {
		return fmt.Errorf("failed to derive node %v private key from path secret: %v", nodeIndex, err)
	}
	privTree[int(nodeIndex)] = nodePriv

	for {
		var ok bool
		nodeIndex, ok = tree.numLeaves().parent(nodeIndex)
		if !ok {
			break
		}

		pathSecret, err := cs.deriveSecret(pathSecret, []byte("path"))
		if err != nil {
			return fmt.Errorf("failed to derive path secret: %v", err)
		}

		nodePriv, err := nodePrivFromPathSecret(cs, pathSecret, tree.get(nodeIndex).encryptionKey())
		if err != nil {
			return fmt.Errorf("failed to derive node %v private key from path secret: %v", nodeIndex, err)
		}
		privTree[int(nodeIndex)] = nodePriv
	}

	return nil
}

// UnmarshalAndProcessMessage decodes a raw MLS message intended for the group
// and processes it.
//
// If the MLS message contains encrypted application data, the decrypted data
// is returned.
func (group *Group) UnmarshalAndProcessMessage(raw []byte) ([]byte, error) {
	var msg mlsMessage
	if err := unmarshal([]byte(raw), &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MLS message: %v", err)
	}

	switch msg.wireFormat {
	case wireFormatMLSPublicMessage:
		return nil, group.processPublicMessage(msg.publicMessage)
	case wireFormatMLSPrivateMessage:
		return group.processPrivateMessage(msg.privateMessage)
	default:
		// TODO: support other wire formats
		return nil, fmt.Errorf("mls: unsupported wire format: %v", msg.wireFormat)
	}
}

func (group *Group) processPublicMessage(pubMsg *publicMessage) error {
	authContent, err := group.verifyPublicMessage(pubMsg)
	if err != nil {
		return fmt.Errorf("failed to verify public message: %v", err)
	}

	switch authContent.content.contentType {
	case contentTypeProposal:
		return group.processProposal(authContent)
	case contentTypeCommit:
		return group.processCommit(authContent, nil, nil, nil)
	case contentTypeApplication:
		return fmt.Errorf("mls: application content type must be encrypted")
	default:
		// TODO: support other content types
		return fmt.Errorf("mls: unsupported content type: %v", authContent.content.contentType)
	}
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

func (group *Group) processPrivateMessage(privMsg *privateMessage) ([]byte, error) {
	cs := group.groupContext.cipherSuite

	if !privMsg.groupID.Equal(group.groupContext.groupID) {
		return nil, fmt.Errorf("mls: message group ID mismatch")
	}
	if privMsg.epoch != group.groupContext.epoch {
		return nil, fmt.Errorf("mls: epoch mismatch: got %v, want %v", privMsg.epoch, group.groupContext.epoch)
	}

	senderDataSecret, err := cs.deriveSecret(group.epochSecret, secretLabelSenderData)
	if err != nil {
		return nil, fmt.Errorf("failed to derive sender data secret: %v", err)
	}

	senderData, err := privMsg.decryptSenderData(cs, senderDataSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt sender data: %v", err)
	}

	encryptionSecret, err := cs.deriveSecret(group.epochSecret, secretLabelEncryption)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption secret: %v", err)
	}

	secretTree, err := deriveSecretTree(cs, group.tree.numLeaves(), encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to erive secret tree: %v", err)
	}

	label := ratchetLabelFromContentType(privMsg.contentType)
	secret, err := secretTree.deriveRatchetRoot(cs, senderData.leafIndex.nodeIndex(), label)
	if err != nil {
		return nil, fmt.Errorf("failed to derive secret ratchet tree root: %v", err)
	}

	// TODO: limit number of iterations
	// TODO: erase knowledge about used generations to ensure forward secrecy
	for secret.generation != senderData.generation {
		secret, err = secret.deriveNext(cs)
		if err != nil {
			return nil, fmt.Errorf("failed to derive next ratchet secret: %v", err)
		}
	}

	privContent, err := privMsg.decryptContent(cs, secret, senderData.reuseGuard)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private message content: %v", err)
	}

	signerNode := group.tree.getLeaf(senderData.leafIndex)
	if signerNode == nil {
		return nil, fmt.Errorf("mls: signer node is blank")
	}

	authContent := privMsg.authenticatedContent(senderData, privContent)
	if !authContent.verifySignature(signerNode.signatureKey, &group.groupContext) {
		return nil, fmt.Errorf("failed to verify private message content signature: %v", err)
	}

	switch authContent.content.contentType {
	case contentTypeProposal:
		return nil, group.processProposal(authContent)
	case contentTypeCommit:
		return nil, group.processCommit(authContent, nil, nil, nil)
	case contentTypeApplication:
		return authContent.content.applicationData, nil
	default:
		// TODO: support other content types
		return nil, fmt.Errorf("mls: unsupported content type: %v", authContent.content.contentType)
	}
}

func (group *Group) processProposal(authContent *authenticatedContent) error {
	if authContent.content.contentType != contentTypeProposal {
		panic("mls: expected a proposal")
	}
	proposal := authContent.content.proposal

	ref, err := authContent.generateProposalRef(group.groupContext.cipherSuite)
	if err != nil {
		return fmt.Errorf("failed to generate proposal ref: %v", err)
	}

	group.pendingProposals = append(group.pendingProposals, pendingProposal{
		ref:      ref,
		proposal: proposal,
		sender:   authContent.content.sender.leafIndex,
	})
	return nil
}

func (group *Group) processCommit(authContent *authenticatedContent, pskIDs []preSharedKeyID, psks [][]byte, now func() time.Time) error {
	cs := group.groupContext.cipherSuite
	senderLeafIndex := authContent.content.sender.leafIndex

	if authContent.content.contentType != contentTypeCommit {
		panic("mls: expected a commit")
	}
	commit := authContent.content.commit

	proposals, senders, err := resolveProposals(commit.proposals, senderLeafIndex, group.pendingProposals)
	if err != nil {
		return err
	}

	if err := verifyProposalList(proposals, senders, senderLeafIndex); err != nil {
		return fmt.Errorf("failed to verify proposals: %v", err)
	}

	for _, prop := range proposals {
		if prop.proposalType == proposalTypeAdd {
			if err := prop.add.keyPackage.verify(&group.groupContext); err != nil {
				return fmt.Errorf("failed to verify add proposal: %v", err)
			}
		}
	}

	// TODO: additional proposal list checks

	if proposalListNeedsPath(proposals) && commit.path == nil {
		return fmt.Errorf("mls: commit is missing update path but required by proposal list")
	}

	newGroupCtx := group.groupContext
	newGroupCtx.epoch++

	newTree := group.tree.copy()
	newTree.apply(proposals, senders)

	newPrivTree := make([][]byte, len(newTree))
	for i := range group.tree {
		if i < len(newPrivTree) {
			newPrivTree[i] = group.privTree[i]
		}
	}

	_, kdf, _ := cs.hpke().Params()
	commitSecret := make([]byte, kdf.ExtractSize())
	if commit.path != nil {
		if commit.path.leafNode.leafNodeSource != leafNodeSourceCommit {
			return fmt.Errorf("mls: commit path leaf node source must be commit")
		}

		// TODO: check tree length
		senderNode := newTree.getLeaf(senderLeafIndex)

		// The same signature key can be re-used, but the encryption key
		// must change
		signatureKeys, encryptionKeys := newTree.keys()
		delete(signatureKeys, string(senderNode.signatureKey))
		err := commit.path.leafNode.verify(&leafNodeVerifyOptions{
			cipherSuite:    cs,
			groupID:        group.groupContext.groupID,
			leafIndex:      senderLeafIndex,
			supportedCreds: newTree.supportedCreds(),
			signatureKeys:  signatureKeys,
			encryptionKeys: encryptionKeys,
			now:            now,
		})
		if err != nil {
			return fmt.Errorf("failed to verify leaf node: %v", err)
		}

		for _, updateNode := range commit.path.nodes {
			if _, dup := encryptionKeys[string(updateNode.encryptionKey)]; dup {
				return fmt.Errorf("mls: encryption key in update path already used in ratchet tree")
			}
		}

		if err := newTree.mergeUpdatePath(cs, senderLeafIndex, commit.path); err != nil {
			return fmt.Errorf("failed to merge update path in ratchet tree: %v", err)
		}

		newGroupCtx.treeHash, err = newTree.computeRootTreeHash(cs)
		if err != nil {
			return fmt.Errorf("failed to compute root tree hash: %v", err)
		}

		// TODO: update group context extensions

		commitSecret, err = newTree.decryptPathSecrets(cs, &newGroupCtx, senderLeafIndex, group.myLeafIndex, commit.path, newPrivTree)
		if err != nil {
			return fmt.Errorf("failed to decrypt path secrets: %v", err)
		}
	} else {
		// TODO: only recompute parts of the tree affected by proposals
		newGroupCtx.treeHash, err = newTree.computeRootTreeHash(cs)
		if err != nil {
			return fmt.Errorf("failed to compute root tree hash: %v", err)
		}
	}

	newGroupCtx.confirmedTranscriptHash, err = authContent.confirmedTranscriptHashInput().hash(cs, group.interimTranscriptHash)
	if err != nil {
		return fmt.Errorf("failed to hash confirmed transcript hash input: %v", err)
	}

	newInterimTranscriptHash, err := nextInterimTranscriptHash(cs, newGroupCtx.confirmedTranscriptHash, authContent.auth.confirmationTag)
	if err != nil {
		return fmt.Errorf("failed to compute next interim transcript hash: %v", err)
	}

	newJoinerSecret, err := newGroupCtx.extractJoinerSecret(group.initSecret, commitSecret)
	if err != nil {
		return fmt.Errorf("failed to extract joined secret: %v", err)
	}

	newPSKSecret, err := extractPSKSecret(cs, pskIDs, psks)
	if err != nil {
		return fmt.Errorf("failed to extract PSK secret: %v", err)
	}

	newEpochSecret, err := newGroupCtx.extractEpochSecret(newJoinerSecret, newPSKSecret)
	if err != nil {
		return fmt.Errorf("failed to extract epoch secret: %v", err)
	}

	newInitSecret, err := cs.deriveSecret(newEpochSecret, secretLabelInit)
	if err != nil {
		return fmt.Errorf("failed to erive init secret: %v", err)
	}

	group.tree = newTree
	group.privTree = newPrivTree
	group.groupContext = newGroupCtx
	group.interimTranscriptHash = newInterimTranscriptHash
	group.pskSecret = newPSKSecret
	group.epochSecret = newEpochSecret
	group.initSecret = newInitSecret
	group.pendingProposals = nil // TODO: only clear proposals we've consumed
	return nil
}

func resolveProposals(proposalOrRefs []proposalOrRef, senderLeafIndex leafIndex, pendingProposals []pendingProposal) ([]proposal, []leafIndex, error) {
	var (
		proposals []proposal
		senders   []leafIndex
	)
	for _, propOrRef := range proposalOrRefs {
		switch propOrRef.typ {
		case proposalOrRefTypeProposal:
			proposals = append(proposals, *propOrRef.proposal)
			senders = append(senders, senderLeafIndex)
		case proposalOrRefTypeReference:
			var found bool
			for _, pp := range pendingProposals {
				if pp.ref.Equal(propOrRef.reference) {
					found = true
					proposals = append(proposals, *pp.proposal)
					senders = append(senders, pp.sender)
					break
				}
			}
			if !found {
				return nil, nil, fmt.Errorf("mls: cannot find proposal reference: %v", propOrRef.reference)
			}
		}
	}

	return proposals, senders, nil
}

// CreateWelcome creates a new welcome message, inviting a new member to the
// group.
//
// The welcome message should be sent to the new member. Alongside the welcome
// message, a raw MLS message is returned and must be consumed by all existing
// members of the group to add the new member.
func (group *Group) CreateWelcome(keyPkg *KeyPackage) (*Welcome, []byte, error) {
	// TODO: missing steps from section 12.4.1
	cs := group.groupContext.cipherSuite

	prop := proposal{
		proposalType: proposalTypeAdd,
		add:          &add{keyPackage: *keyPkg},
	}

	// TODO: check proposal list validity per section 12.2
	commit := commit{
		proposals: []proposalOrRef{
			{
				typ:      proposalOrRefTypeProposal,
				proposal: &prop,
			},
		},
	}

	newGroupCtx := group.groupContext
	newGroupCtx.epoch++

	newTree := group.tree.copy()
	newTree.apply([]proposal{prop}, []leafIndex{group.myLeafIndex})

	// TODO: only recompute parts of the tree affected by proposals
	var err error
	newGroupCtx.treeHash, err = newTree.computeRootTreeHash(cs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute root tree hash: %v", err)
	}

	_, kdf, _ := cs.hpke().Params()
	commitSecret := make([]byte, kdf.ExtractSize())

	pskSecret, err := extractPSKSecret(cs, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract PSK secret: %v", err)
	}

	framedContent := framedContent{
		groupID: group.groupContext.groupID,
		epoch:   group.groupContext.epoch,
		sender: sender{
			senderType: senderTypeMember,
			leafIndex:  group.myLeafIndex,
		},
		contentType: contentTypeCommit,
		commit:      &commit,
	}

	pubMsg, err := signPublicMessage(cs, group.signaturePriv, &framedContent, &group.groupContext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign public message: %v", err)
	}

	authContent := pubMsg.authenticatedContent()
	newGroupCtx.confirmedTranscriptHash, err = authContent.confirmedTranscriptHashInput().hash(cs, group.interimTranscriptHash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash confirmed transcript hash input: %v", err)
	}

	joinerSecret, err := newGroupCtx.extractJoinerSecret(group.initSecret, commitSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract joiner secret: %v", err)
	}

	epochSecret, err := newGroupCtx.extractEpochSecret(joinerSecret, pskSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract epoch secret: %v", err)
	}

	confirmationTag, err := newGroupCtx.signConfirmationTag(epochSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign confirmation tag: %v", err)
	}
	pubMsg.auth.confirmationTag = confirmationTag

	membershipKey, err := group.groupContext.cipherSuite.deriveSecret(group.epochSecret, secretLabelMembership)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive membership key: %v", err)
	}
	if err := pubMsg.signMembershipTag(cs, membershipKey, &group.groupContext); err != nil {
		return nil, nil, fmt.Errorf("failed to sign public message membership tag: %v", err)
	}

	rawTree, err := marshal(newTree)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ratchet tree: %v", err)
	}

	newGroupInfo := groupInfo{
		groupContext:    newGroupCtx,
		confirmationTag: confirmationTag,
		signer:          group.myLeafIndex,
		extensions: []extension{
			{
				extensionType: extensionTypeRatchetTree,
				extensionData: rawTree,
			},
		},
	}
	if err := newGroupInfo.sign(group.signaturePriv); err != nil {
		return nil, nil, fmt.Errorf("failed to sign group info: %v", err)
	}

	keyPkgRef, err := keyPkg.GenerateRef()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key package ref: %v", err)
	}

	encryptedGroupInfo, err := newGroupInfo.encrypt(joinerSecret, pskSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt group info: %v", err)
	}

	groupSecrets := groupSecrets{joinerSecret: joinerSecret}
	rawEncryptedGroupSecrets, err := groupSecrets.encrypt(cs, keyPkg.initKey, encryptedGroupInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt group secrets: %v", err)
	}

	rawMsg, err := marshal(&mlsMessage{
		version:       protocolVersionMLS10,
		wireFormat:    wireFormatMLSPublicMessage,
		publicMessage: pubMsg,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public message: %v", err)
	}

	return &Welcome{
		cipherSuite: cs,
		secrets: []encryptedGroupSecrets{
			{
				newMember:             keyPkgRef,
				encryptedGroupSecrets: *rawEncryptedGroupSecrets,
			},
		},
		encryptedGroupInfo: encryptedGroupInfo,
	}, rawMsg, nil
}

// CreateApplicationMessage creates a new encrypted application message for the
// group. The message contains an arbitrary application-specific payload.
func (group *Group) CreateApplicationMessage(data []byte) ([]byte, error) {
	cs := group.groupContext.cipherSuite

	senderData, err := newSenderData(group.myLeafIndex, 0) // TODO: set generation > 0
	if err != nil {
		return nil, fmt.Errorf("failed to create sender data: %v", err)
	}

	encryptionSecret, err := cs.deriveSecret(group.epochSecret, secretLabelEncryption)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption secret: %v", err)
	}

	secretTree, err := deriveSecretTree(cs, group.tree.numLeaves(), encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to erive secret tree: %v", err)
	}

	label := ratchetLabelFromContentType(contentTypeApplication)
	secret, err := secretTree.deriveRatchetRoot(cs, group.myLeafIndex.nodeIndex(), label)
	if err != nil {
		return nil, fmt.Errorf("failed to derive secret ratchet tree root: %v", err)
	}

	senderDataSecret, err := cs.deriveSecret(group.epochSecret, secretLabelSenderData)
	if err != nil {
		return nil, fmt.Errorf("failed to derive sender data secret: %v", err)
	}

	framedContent := framedContent{
		groupID: group.groupContext.groupID,
		epoch:   group.groupContext.epoch,
		sender: sender{
			senderType: senderTypeMember,
			leafIndex:  group.myLeafIndex,
		},
		contentType:     contentTypeApplication,
		applicationData: data,
	}
	privMsg, err := encryptPrivateMessage(cs, group.signaturePriv, secret, senderDataSecret, &framedContent, senderData, &group.groupContext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private message: %v", err)
	}

	rawMsg, err := marshal(&mlsMessage{
		version:        protocolVersionMLS10,
		wireFormat:     wireFormatMLSPrivateMessage,
		privateMessage: privMsg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private message: %v", err)
	}

	return rawMsg, nil
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

func (info *groupInfo) sign(signerPriv []byte) error {
	cs := info.groupContext.cipherSuite
	tbs, err := marshal((*groupInfoTBS)(info))
	if err != nil {
		return err
	}
	sig, err := cs.signWithLabel(signerPriv, []byte("GroupInfoTBS"), tbs)
	if err != nil {
		return err
	}
	info.signature = sig
	return nil
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

func (info *groupInfo) encrypt(joinerSecret, pskSecret []byte) ([]byte, error) {
	cs := info.groupContext.cipherSuite
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

	cipher, err := aead.New(welcomeKey)
	if err != nil {
		return nil, err
	}

	rawGroupInfo, err := marshal(info)
	if err != nil {
		return nil, err
	}

	return cipher.Seal(nil, welcomeNonce, rawGroupInfo, nil), nil
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

func (sec *groupSecrets) encrypt(cs CipherSuite, initKey, encryptedGroupInfo []byte) (*hpkeCiphertext, error) {
	rawGroupSecrets, err := marshal(sec)
	if err != nil {
		return nil, err
	}

	kemOutput, ciphertext, err := cs.encryptWithLabel(initKey, []byte("Welcome"), encryptedGroupInfo, rawGroupSecrets)
	if err != nil {
		return nil, err
	}

	return &hpkeCiphertext{
		kemOutput:  kemOutput,
		ciphertext: ciphertext,
	}, nil
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

// Bytes encodes the welcome message.
func (w *Welcome) Bytes() []byte {
	raw, err := marshal(&mlsMessage{
		version:    protocolVersionMLS10,
		wireFormat: wireFormatMLSWelcome,
		welcome:    w,
	})
	if err != nil {
		// should never happen
		panic(fmt.Errorf("mls: failed to marshal welcome message: %v", err))
	}
	return raw
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
