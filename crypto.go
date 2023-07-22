package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

type (
	hpkePublicKey      []byte
	signaturePublicKey []byte
)

type credentialType uint16

// https://www.iana.org/assignments/mls/mls.xhtml#mls-credential-types
const (
	credentialTypeBasic credentialType = 0x0001
	credentialTypeX509  credentialType = 0x0002
)

type credential struct {
	credentialType credentialType
	identity       []byte   // for credentialTypeBasic
	certificates   [][]byte // for credentialTypeX509
}

func (cred *credential) unmarshal(s *cryptobyte.String) error {
	*cred = credential{}

	if !s.ReadUint16((*uint16)(&cred.credentialType)) {
		return io.ErrUnexpectedEOF
	}

	switch cred.credentialType {
	case credentialTypeBasic:
		if !readOpaqueVec(s, &cred.identity) {
			return io.ErrUnexpectedEOF
		}
		return nil
	case credentialTypeX509:
		return readVector(s, func(s *cryptobyte.String) error {
			var cert []byte
			if !readOpaqueVec(s, &cert) {
				return io.ErrUnexpectedEOF
			}
			cred.certificates = append(cred.certificates, cert)
			return nil
		})
	default:
		return fmt.Errorf("mls: invalid credential type %d", cred.credentialType)
	}
}
