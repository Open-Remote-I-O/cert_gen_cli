package utils

import (
	"fmt"
	"net"
	"os"

	"github.com/pelletier/go-toml/v2"
)

type CertGenConfig struct {
	OrganizationName  string
	SubjectCommonName string
	DnsNames          []string
	IPAddresses       []net.IP
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
