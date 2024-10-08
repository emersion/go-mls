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
	CredentialTypeBasic credentialType = 0x0001
	CredentialTypeX509  credentialType = 0x0002
)

type Credential struct {
	CredentialType credentialType
	Identity       []byte   // for credentialTypeBasic
	Certificates   [][]byte // for credentialTypeX509
}

func (cred *Credential) unmarshal(s *cryptobyte.String) error {
	*cred = Credential{}

	if !s.ReadUint16((*uint16)(&cred.CredentialType)) {
		return io.ErrUnexpectedEOF
	}

	switch cred.CredentialType {
	case CredentialTypeBasic:
		if !readOpaqueVec(s, &cred.Identity) {
			return io.ErrUnexpectedEOF
		}
		return nil
	case CredentialTypeX509:
		return readVector(s, func(s *cryptobyte.String) error {
			var cert []byte
			if !readOpaqueVec(s, &cert) {
				return io.ErrUnexpectedEOF
			}
			cred.Certificates = append(cred.Certificates, cert)
			return nil
		})
	default:
		return fmt.Errorf("mls: invalid credential type %d", cred.CredentialType)
	}
}

func (cred *Credential) marshal(b *cryptobyte.Builder) {
	b.AddUint16(uint16(cred.CredentialType))
	switch cred.CredentialType {
	case CredentialTypeBasic:
		writeOpaqueVec(b, cred.Identity)
	case CredentialTypeX509:
		writeVector(b, len(cred.Certificates), func(b *cryptobyte.Builder, i int) {
			writeOpaqueVec(b, cred.Certificates[i])
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
