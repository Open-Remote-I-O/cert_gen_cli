package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/Open-Remote-I-O/cert_gen_cli/utils"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const (
	crtFileExtension = ".crt"
	keyFileExtension = ".key"
)

var (
	FilePath          string
	CaCertName        string
	SubjectCommonName string
)

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

		randomSn, err := utils.GenerateRandomThreeBytesSN()
		if err != nil {
			fmt.Println("Error while generating random CA serial number:", err)
			return
		}

		if OrganizationName == "" {
			OrganizationName = utils.InputPrompt("Input your organization name:")
		}

		if SubjectCommonName == "" {
			OrganizationName = utils.InputPrompt("Input subject common name:")
		}

		// Create certificate template
		caTmpl := x509.Certificate{
			SerialNumber: randomSn,
			Subject: pkix.Name{
				Organization: []string{OrganizationName},
				CommonName:   SubjectCommonName,
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
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
				return err
			}
			certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert})
			caCrtFilePath := utils.GenFilePath(FilePath, CaCertName, crtFileExtension)
			if err = os.WriteFile(caCrtFilePath, certPem, 0644); err != nil {
				return err
			}
			return nil
		})

		errGroup.Go(func() error {
			// Encode private key in PEM format
			binPrivKey, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
			if err != nil {
				return err
			}
			privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: binPrivKey})
			if err = os.WriteFile(utils.GenFilePath(FilePath, CaCertName, keyFileExtension), privKeyPem, 0644); err != nil {
				return err
			}
			return nil
		})

		if err := errGroup.Wait(); err != nil {
			// Cleanup eventual leftovers
			fmt.Println("Error occured while generating keypair", err)

			fmt.Println("Cleaning up leftovers...")

			os.Remove(utils.GenFilePath(FilePath, CaCertName, crtFileExtension))

			os.Remove(utils.GenFilePath(FilePath, CaCertName, keyFileExtension))
			return
		}
		fmt.Println("Successfully created CA keypair")
	},
}

func init() {
	rootCmd.AddCommand(genCaKeysCmd)

	genCaKeysCmd.Flags().StringVarP(&FilePath, "path", "o", "./", `path to output CA certificate and key PEM file into.`)
	genCaKeysCmd.Flags().StringVarP(&CaCertName, "name", "n", "ca", `ca cert and key name.`)

	genCaKeysCmd.Flags().
		StringVar(&OrganizationName, "organization-name", "", `organization name to have in the newly generated CA certificate.`)

	genCaKeysCmd.Flags().
		StringVar(&SubjectCommonName, "subject-common-name", "", `subject common name to have in the newly generated CA certificate.`)
}
