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

// A Credential holds information about a group member's identity.
type Credential struct {
	credentialType credentialType
	identity       []byte   // for credentialTypeBasic
	certificates   [][]byte // for credentialTypeX509
}

func (cred *Credential) unmarshal(s *cryptobyte.String) error {
	*cred = Credential{}

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

func (cred *Credential) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(cred.credentialType))
	switch cred.credentialType {
	case credentialTypeBasic:
		writeOpaqueVec(b, cred.identity)
	case credentialTypeX509:
		writeVector(b, len(cred.certificates), func(b *cryptobyte.Builder, i int) {
			writeOpaqueVec(b, cred.certificates[i])
		})
	default:
		panic("unreachable")
	}
}

type hpkeCiphertext struct {
	kemOutput  []byte
	ciphertext []byte
}

func (hpke *hpkeCiphertext) unmarshal(s *cryptobyte.String) error {
	*hpke = hpkeCiphertext{}
	if !readOpaqueVec(s, &hpke.kemOutput) || !readOpaqueVec(s, &hpke.ciphertext) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (hpke *hpkeCiphertext) marshal(b *cryptobyte.Builder) {
	writeOpaqueVec(b, hpke.kemOutput)
	writeOpaqueVec(b, hpke.ciphertext)
}
