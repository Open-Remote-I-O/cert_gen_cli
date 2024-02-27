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

var (
	ParentFilePath = "./"
	ParentCertName = "client.crt"
	CaCertFilePath = "./ca.crt"
	CaKeyFilePath  = "./ca.key"
)

func parseCaCertificate() (*x509.Certificate, error) {
	rawPemCert, err := os.ReadFile(CaCertFilePath)
	if err != nil {
		fmt.Println("Error reading CA certificate:", err)
		return nil, err
	}

	decodedCaCert, _ := pem.Decode(rawPemCert)

	caCert, err := x509.ParseCertificate(decodedCaCert.Bytes)
	if err != nil {
		fmt.Println("Error parsing CA certificate:", err)
		return nil, err
	}

	return caCert, nil
}

// genCaParentCertCmd represents the genCaParentCert command
var genCaParentCertCmd = &cobra.Command{
	Use:   "genCaParentCert",
	Short: "create sub certificate from a CA cert",
	Long:  `creates a keypair for a client using a CA root certificate`,
	Run: func(cmd *cobra.Command, args []string) {
		caCert, err := parseCaCertificate()
		if err != nil {
			return
		}

		rawCaKey, err := os.ReadFile(CaKeyFilePath)
		if err != nil {
			fmt.Println("Error reading CA key from specified path: \n  err:", CaKeyFilePath, err)
			return
		}

		decodedCaKey, _ := pem.Decode(rawCaKey)

		parsedCaKey, err := x509.ParsePKCS8PrivateKey(decodedCaKey.Bytes)
		if err != nil {
			fmt.Println("Error parsing CA key:", err)
			return
		}

		serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println("Error generate private key:", err)
			return
		}

		randomSn, err := utils.GenerateRandomThreeBytesSN()
		if err != nil {
			fmt.Println("Error while generating random CA serial number:", err)
			return
		}

		serverCertTmpl := x509.Certificate{
			SerialNumber: randomSn,
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
				parsedCaKey,
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
		fmt.Println("Successfully generated parent keypair from CA keypair")
	},
}

func init() {
	rootCmd.AddCommand(genCaParentCertCmd)

	genCaParentCertCmd.Flags().StringP("output", "o", ParentFilePath, `output path for new certificate.`)
	genCaParentCertCmd.Flags().StringP("name", "n", ParentCertName, `ca cert and key name.`)
	genCaParentCertCmd.Flags().StringP("ca-cert-path", "c", CaCertFilePath, `path to read the ca cert from.`)
	genCaParentCertCmd.Flags().StringP("ca-key-path", "k", CaKeyFilePath, `path to read the ca private key from.`)
}
