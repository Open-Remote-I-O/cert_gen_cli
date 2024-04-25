package utils

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/pelletier/go-toml/v2"
)

type CertificateMetadata struct {
	OrganizationName  string
	SubjectCommonName string
	DnsNames          []string
	IPAddresses       []net.IP
}

type EncryptionAlgorithm struct {
	EncAlgorithm string
	EncBits      int
}

type CertGenConfig struct {
	CertificateMetadata CertificateMetadata
	EncryptionAlgorithm EncryptionAlgorithm
}

var ValidEDCSABits = map[int]elliptic.Curve{
	224: elliptic.P224(),
	256: elliptic.P256(),
	384: elliptic.P384(),
	521: elliptic.P521(),
}

var ValidRSABits = map[int]*bool{
	521:  nil,
	1024: nil,
	2048: nil,
	4096: nil,
}

func (em *EncryptionAlgorithm) ValidateEncryptionBitsRequested() error {
	switch em.EncAlgorithm {
	case "RSA":
		if _, ok := ValidRSABits[em.EncBits]; !ok {
			return errors.New("provied encryption bits value for RSA algorithm is not valid")
		}
	case "EDCSA":
		if _, ok := ValidEDCSABits[em.EncBits]; !ok {
			return errors.New("provied encryption bits value for EDCSA algorithm is not valid")
		}
	default:
		return errors.New("encryption algorithm provided is not valid")
	}
	return errors.New("encryption algorithm provided is not valid")
}

func (em *EncryptionAlgorithm) ParseSupportedEnc() SupportedEnc {
	switch em.EncAlgorithm {
	case "RSA":
		return RSA
	case "EDCSA":
		return EDCSA
	default:
		return Undefined
	}
}

func ParseCertGenConfig(path string) (*CertGenConfig, error) {
	var conf CertGenConfig

	certGenTomlConf, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading toml file from path:", path, err)
		return &conf, err
	}
	err = toml.Unmarshal(certGenTomlConf, &conf)
	if err != nil {
		fmt.Println("Error decoding toml config:", err)
		return &CertGenConfig{}, err
	}
	return &conf, nil
}
