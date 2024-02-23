package cmd

import (
	"cert_gen_cli/utils"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var FilePath string
var CaCertName string

// genCaKeysCmd represents the genCaKeys command
var genCaKeysCmd = &cobra.Command{
	Use:   "genCaKeys",
	Short: "generate root ca certificate and private key",
	Long: `generate root ca certificate and private key
	see flags for more informations about the tool`,
	Run: func(cmd *cobra.Command, args []string) {
		caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println("Error generating CA private key:", err)
			return
		}

		// Create certificate template
		caTmpl := x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{utils.InputPrompt("Input your organization name:")},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}

		errGroup := new(errgroup.Group)

		// Create certificate and encode in PEM format
		errGroup.Go(func() error {
			caCert, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, caPrivKey.Public(), caPrivKey)
			if err != nil {
				fmt.Println("Error creating certificate:", err)
				return err
			}
			certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert})

			caCrtFilePath := utils.GenFilePath(FilePath, CaCertName, crtFileExtension)
			// Write certificate and key to files
			if err = os.WriteFile(caCrtFilePath, certPem, 0644); err != nil {
				fmt.Println("Error writing certificate:", err)
				return err
			}
			return nil
		})

		errGroup.Go(func() error {
			// Encode private key in PEM format
			binPrivKey, err := x509.MarshalECPrivateKey(caPrivKey)
			if err != nil {
				fmt.Println("Error creating private key:", err)
				return err
			}

			privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: binPrivKey})
			if err = os.WriteFile(utils.GenFilePath(FilePath, CaCertName, keyFileExtension), privKeyPem, 0644); err != nil {
				fmt.Println("Error writing private key:", err)
				return err
			}
			return nil
		})

		if err := errGroup.Wait(); err != nil {
			// Cleanup eventual leftovers
			fmt.Println("Error occured while generating keypair", err)

			fmt.Println("Cleaning up leftovers...")

			os.Remove(utils.GenFilePath(ParentFilePath, ParentCertName, keyFileExtension))

			os.Remove(utils.GenFilePath(ParentFilePath, ParentCertName, keyFileExtension))
			return
		}
		fmt.Println("Successfully created CA keypair")
	},
}

func init() {
	rootCmd.AddCommand(genCaKeysCmd)

	// Setting default path to write into
	FilePath := "./"
	CaCertName := "ca"

	genCaKeysCmd.Flags().StringP("path", "p", FilePath, `define path to ca certificate into.`)
	genCaKeysCmd.Flags().StringP("name", "n", CaCertName, `define ca cert and key name.`)
}
