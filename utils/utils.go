package utils

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
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
