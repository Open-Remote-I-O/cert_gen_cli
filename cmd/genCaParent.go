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

	"golang.org/x/sync/errgroup"

	"github.com/spf13/cobra"
)

var (
	ParentFilePath string
	ParentCertName string
	CaCertFilePath string
)

// genCaParentCertCmd represents the genCaParentCert command
var genCaParentCertCmd = &cobra.Command{
	Use:   "genCaParentCert",
	Short: "create sub certificate from a CA cert",
	Long:  `creates a keypair for a client using a CA root certificate`,
	Run: func(cmd *cobra.Command, args []string) {
		res, err := os.ReadFile(CaCertFilePath)
		if err != nil {
			fmt.Println("Error reading CA certificate:", err)
			return
		}
		// TODO: eventually tranform this two operations in two concurrent operations sending output to a channel
		serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println("Error generate private key:", err)
			return
		}

		caCert, err := x509.ParseCertificate(res)
		if err != nil {
			fmt.Println("Error parsing CA certificate:", err)
			return
		}

		serverCertTmpl := x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{utils.InputPrompt("Input your organization name:")},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
			Issuer:                caCert.Issuer,
		}

		errGroup := new(errgroup.Group)

		errGroup.Go(func() error {
			serverCert, err := x509.CreateCertificate(
				rand.Reader,
				&serverCertTmpl,
				caCert,
				serverPrivKey.Public(),
				serverPrivKey,
			)
			if err != nil {
				return err
			}

			certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert})

			if err = os.WriteFile(utils.GenFilePath(ParentFilePath, ParentCertName, keyFileExtension), certPem, 0644); err != nil {
				return err
			}
			return nil
		})

		errGroup.Go(func() error {
			// Encode server private key in PEM format
			binServerPrivKey, err := x509.MarshalECPrivateKey(serverPrivKey)
			if err != nil {
				return err
			}
			privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: binServerPrivKey})

			// Write server certificate and key to files
			if err = os.WriteFile(utils.GenFilePath(ParentFilePath, ParentCertName, keyFileExtension), privKeyPem, 0644); err != nil {
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
		fmt.Println("Successfully fetched all URLs.")
	},
}

func init() {
	rootCmd.AddCommand(genCaParentCertCmd)

	// Setting default path to write into
	ParentFilePath := "./"
	ParentCertName := "ca"
	CaCertFilePath := "./"

	genCaParentCertCmd.Flags().StringP("path", "p", ParentFilePath, `define path to generate certificate into.`)
	genCaParentCertCmd.Flags().StringP("name", "n", ParentCertName, `define ca cert and key name.`)
	genCaParentCertCmd.Flags().StringP("ca-cert-path", "c", CaCertFilePath, `define path to read the ca cert from.`)
}
