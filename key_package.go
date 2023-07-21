package mls

type keyPackage struct {
	version     protocolVersion
	cipherSuite cipherSuite
	// TODO
}

type keyPackageRef []byte
