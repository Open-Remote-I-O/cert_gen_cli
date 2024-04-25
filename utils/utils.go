package utils

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
)

type SupportedEnc string

const (
	Undefined SupportedEnc = "Undefined"
	RSA       SupportedEnc = "RSA"
	EDCSA     SupportedEnc = "EDCSA"
)

func GenFilePath(filePath string, name string, extension string) string {
	var filePathBuilder strings.Builder
	filePathBuilder.WriteString(filePath)
	filePathBuilder.WriteString(name)
	filePathBuilder.WriteString(extension)
	return filePathBuilder.String()
}

func InputPrompt(label string) string {
	var s string
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, label+" ")
		s, _ = r.ReadString('\n')
		if s != "" {
			break
		}
	}
	return strings.TrimSpace(s)
}

func GenerateRandomThreeBytesSN() (*big.Int, error) {
	// https://cabforum.org/working-groups/server/baseline-requirements/documents/ at the moment of creating program
	// as stated by version 2.0.1 at least 64 bits of entropy are strongly suggested
	val, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	return val, nil
}

func GenerateUserRequestedKey(e EncryptionAlgorithm) (privateKey any, publicKey any, err error) {
	err = e.ValidateEncryptionBitsRequested()
	if err != nil {
		return nil, nil, err
	}
	switch e.ParseSupportedEnc() {
	case RSA:
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, e.EncBits)
		if err != nil {
			return nil, nil, err
		}
		return rsaPrivateKey, rsaPrivateKey.Public(), nil
	case EDCSA:
		edcsaPrivateKey, err := ecdsa.GenerateKey(ValidEDCSABits[e.EncBits], rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return edcsaPrivateKey, edcsaPrivateKey.Public(), nil
	case Undefined:
		return nil, nil, errors.New("encryption algorithm provided is not valid")
	}
	return nil, nil, errors.New("unexpected error happened while parsing provided encryption algorithm")
}
