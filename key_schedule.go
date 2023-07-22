package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

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

type pskType uint8

const (
	pskTypeExternal   pskType = 1
	pskTypeResumption pskType = 2
)

func (t *pskType) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(t)) {
		return io.ErrUnexpectedEOF
	}
	switch *t {
	case pskTypeExternal, pskTypeResumption:
		return nil
	default:
		return fmt.Errorf("mls: invalid PSK type %d", *t)
	}
}

type resumptionPSKUsage uint8

const (
	resumptionPSKUsageApplication resumptionPSKUsage = 1
	resumptionPSKUsageReinit      resumptionPSKUsage = 2
	resumptionPSKUsageBranch      resumptionPSKUsage = 3
)

func (usage *resumptionPSKUsage) unmarshal(s *cryptobyte.String) error {
	if !s.ReadUint8((*uint8)(usage)) {
		return io.ErrUnexpectedEOF
	}
	switch *usage {
	case resumptionPSKUsageApplication, resumptionPSKUsageReinit, resumptionPSKUsageBranch:
		return nil
	default:
		return fmt.Errorf("mls: invalid resumption PSK usage %d", *usage)
	}
}

type preSharedKeyID struct {
	pskType pskType

	// for pskTypeExternal
	pskID []byte

	// for pskTypeResumption
	usage      resumptionPSKUsage
	pskGroupID GroupID
	pskEpoch   uint64

	pskNonce []byte
}

func (id *preSharedKeyID) unmarshal(s *cryptobyte.String) error {
	*id = preSharedKeyID{}

	if err := id.pskType.unmarshal(s); err != nil {
		return err
	}

	switch id.pskType {
	case pskTypeExternal:
		if !readOpaqueVec(s, &id.pskID) {
			return io.ErrUnexpectedEOF
		}
	case pskTypeResumption:
		if err := id.usage.unmarshal(s); err != nil {
			return err
		}
		if !readOpaqueVec(s, (*[]byte)(&id.pskGroupID)) || !s.ReadUint64(&id.pskEpoch) {
			return io.ErrUnexpectedEOF
		}
	default:
		panic("unreachable")
	}

	if !readOpaqueVec(s, &id.pskNonce) {
		return io.ErrUnexpectedEOF
	}

	return nil
}
