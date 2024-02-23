package utils

import (
	"bufio"
	"fmt"
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
