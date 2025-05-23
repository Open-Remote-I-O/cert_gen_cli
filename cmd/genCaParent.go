package cmd

import (
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
	ParentCertPath string
	ParentKeyPath  string
	ParentCertName string
	CaCertFilePath string
	CaKeyFilePath  string
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
		conf := generateConfig()

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

		parentPrivKey, parentPublicKey, err := utils.GenerateUserRequestedKey(conf.EncryptionAlgorithm)
		if err != nil {
			fmt.Println("Error generating CA private key:", err)
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
				Organization: []string{conf.CertificateMetadata.OrganizationName},
				CommonName:   conf.CertificateMetadata.SubjectCommonName,
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(1, 0, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			Issuer:      caCert.Issuer,
			DNSNames:    conf.CertificateMetadata.DnsNames,
			IPAddresses: conf.CertificateMetadata.IPAddresses,
		}

		errGroup := new(errgroup.Group)

		errGroup.Go(func() error {
			serverCert, err := x509.CreateCertificate(
				rand.Reader,
				&serverCertTmpl,
				caCert,
				parentPublicKey,
				parsedCaKey,
			)
			if err != nil {
				return err
			}

			certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert})

			if err = os.WriteFile(utils.GenFilePath(ParentCertPath, ParentCertName, crtFileExtension), certPem, 0o644); err != nil {
				return err
			}
			return nil
		})

		errGroup.Go(func() error {
			// Encode server private key in PEM format
			binServerPrivKey, err := x509.MarshalPKCS8PrivateKey(parentPrivKey)
			if err != nil {
				return err
			}
			privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: binServerPrivKey})

			// Write server certificate and key to files
			if err = os.WriteFile(utils.GenFilePath(ParentKeyPath, ParentCertName, keyFileExtension), privKeyPem, 0o644); err != nil {
				return err
			}
			return nil
		})
		if err := errGroup.Wait(); err != nil {
			// Cleanup eventual leftovers
			fmt.Println("Error occurred while generating keypair", err)

			fmt.Println("Cleaning up leftovers...")

			os.Remove(utils.GenFilePath(ParentCertPath, ParentCertName, keyFileExtension))

			os.Remove(utils.GenFilePath(ParentKeyPath, ParentCertName, keyFileExtension))
			return
		}
		fmt.Println("Successfully generated parent keypair from CA keypair")
	},
}

func init() {
	rootCmd.AddCommand(genCaParentCertCmd)

	genCaParentCertCmd.Flags().StringVar(&ParentCertPath, "cert-out", "./", "output path for new parent certificate.")

	genCaParentCertCmd.Flags().StringVar(&ParentKeyPath, "key-out", "./", "output path for new parent private key.")

	genCaParentCertCmd.Flags().StringVarP(&ParentCertName, "name", "n", "client", `ca cert and key name.`)

	genCaParentCertCmd.Flags().StringVarP(&CaCertFilePath, "ca-cert-path", "c", "./ca.crt", `path to read the ca cert from.`)

	genCaParentCertCmd.Flags().
		StringVarP(&CaKeyFilePath, "ca-key-path", "k", "./ca.key", `path to read the ca private key from.`)

	genCaParentCertCmd.Flags().
		StringVar(&OrganizationName, "organization-name", "", `organization name to have in the newly generated certificate.`)

	genCaParentCertCmd.Flags().
		StringVar(&SubjectCommonName, "subject-common-name", "", `subject common name to have in the newly generated certificate.`)

	genCaParentCertCmd.Flags().
		StringVar(&ConfigFilePath, "config-file-path", "", `configuration file path in order to generate parent certificate from`)
}
