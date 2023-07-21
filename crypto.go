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

func unmarshalCredential(s *cryptobyte.String) (*credential, error) {
	var cred credential
	if !s.ReadUint16((*uint16)(&cred.credentialType)) {
		return nil, io.ErrUnexpectedEOF
	}

	switch cred.credentialType {
	case credentialTypeBasic:
		if !readOpaque(s, &cred.identity) {
			return nil, io.ErrUnexpectedEOF
		}
	case credentialTypeX509:
		err := readVector(s, func(s *cryptobyte.String) error {
			var cert []byte
			if !readOpaque(s, &cert) {
				return io.ErrUnexpectedEOF
			}
			cred.certificates = append(cred.certificates, cert)
			return nil
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("mls: invalid credential type %d", cred.credentialType)
	}

	return &cred, nil
}
