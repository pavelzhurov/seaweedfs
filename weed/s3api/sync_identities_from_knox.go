package s3api

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/pinterest/knox"
)

// keyFolder is the directory where keys are cached
const keyFolder = "/var/lib/knox/v0/keys/"

func LoadCertificates(paths []string) ([]tls.Certificate, error) {
	certs := []tls.Certificate{}
	keys := []tls.Certificate{}

	for _, p := range paths {
		d, f := filepath.Split(p)

		g := glob.MustCompile(f, '/')

		err := filepath.Walk(d, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !g.Match(info.Name()) {
				return nil
			}

			cert, err := addBlocks(path)
			if err != nil {
				return err
			}

			if len(cert.Certificate) > 0 {
				certs = append(certs, cert)
			}

			if cert.PrivateKey != nil {
				keys = append(keys, cert)
			}

			return nil
		})

		if err != nil {
			return certs, err
		}
	}

	for i := range certs {
		// We don't need to parse the public key for TLS, but we so do anyway
		// to check that it looks sane and matches the private key.
		x509Cert, err := x509.ParseCertificate(certs[i].Certificate[0])
		if err != nil {
			return certs, nil
		}

		switch pub := x509Cert.PublicKey.(type) {
		case *rsa.PublicKey:
			for _, key := range keys {
				priv, ok := key.PrivateKey.(*rsa.PrivateKey)
				if !ok {
					continue
				}
				if pub.N.Cmp(priv.N) != 0 {
					continue
				}

				certs[i].PrivateKey = priv
				break
			}
		case *ecdsa.PublicKey:
			for _, key := range keys {
				priv, ok := key.PrivateKey.(*ecdsa.PrivateKey)
				if !ok {
					continue
				}
				if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
					continue
				}

				certs[i].PrivateKey = priv
				break
			}
		case ed25519.PublicKey:
			for _, key := range keys {
				priv, ok := key.PrivateKey.(ed25519.PrivateKey)
				if !ok {
					continue
				}
				if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
					continue
				}

				certs[i].PrivateKey = priv
				break
			}
		default:
			return certs, errors.New("tls: unknown public key algorithm")
		}
	}

	return certs, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

func addBlocks(path string) (tls.Certificate, error) {
	cert := tls.Certificate{}

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return cert, err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else if !(block.Type == "PRIVATE KEY" || strings.HasSuffix(block.Type, " PRIVATE KEY")) {
		} else if key, err := parsePrivateKey(block.Bytes); err != nil {
			return cert, fmt.Errorf("failure reading private key from \"%s\": %s", path, err)
		} else {
			cert.PrivateKey = key
		}

		raw = rest
	}

	return cert, nil
}

func authHandler() string {
	_, ok := os.LookupEnv("SPIFFE_CLIENT")
	if ok {
		namespace, ok := os.LookupEnv("NAMESPACE")
		if !ok {
			fmt.Println("NAMESPACE is not defined")
		}
		serviceaccount, ok := os.LookupEnv("POD_SA")
		if !ok {
			fmt.Println("POD_SA is not defined")
		}

		return "0sspiffe://example.org/ns/" + namespace + "/sa/" + serviceaccount
	}
	return ""
}

func (iam *IdentityAccessManagement) syncIdentitiesFromKnox() error {
	// hostname is the host running the knox server
	hostname, ok := os.LookupEnv("KNOX_SERVER")
	if !ok {
		hostname = "knox.knox:9000"
	}

	rand.Seed(time.Now().UTC().UnixNano())

	tlsConfig := &tls.Config{
		ServerName: hostname,
	}
	_, ok = os.LookupEnv("SPIFFE_CLIENT")
	if ok {
		caCertString, ok := os.LookupEnv("KNOX_SERVER_CA")
		if !ok {
			return errors.New("knox CA cert is not provided")
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(caCertString))
		certs, err := LoadCertificates([]string{"/certs/*.key", "/certs/*.pem"})
		if err == nil {
			tlsConfig.Certificates = certs
			tlsConfig.RootCAs = caCertPool
		}
	} else {
		return errors.New("SPIFFE certs are not provided")
	}

	cli := &knox.HTTPClient{
		Host:        hostname,
		AuthHandler: authHandler,
		KeyFolder:   keyFolder,
		Client:      &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
	}

	keys_list, err := cli.GetKeys(map[string]string{})
	if err != nil {
		return fmt.Errorf("can't get keys list. error: %v", err)
	}
	fmt.Println(keys_list)

	for _, key := range keys_list {
		type S3Key struct {
			AccessKey string
			SecretKey string
		}
		var s3key S3Key
		s3keyRaw, err := cli.GetKey(key)
		if err != nil {
			return fmt.Errorf("can't parse s3key %v. data: %+v", key, s3keyRaw)
		}
		s3keyRawData := s3keyRaw.VersionList.GetPrimary().Data
		err = json.Unmarshal(s3keyRawData, &s3key)
		if err != nil {
			return fmt.Errorf("can't parse s3key data %+v", s3keyRawData)
		}
		api_access_key := s3key.AccessKey
		api_secret_key := s3key.SecretKey

		new_ident := true
		for _, ident := range iam.identities {
			// TODO: few credentails support (probably using secret versions)
			if ident.Name == key {
				ident.Credentials = []*Credential{
					{
						AccessKey: api_access_key,
						SecretKey: api_secret_key,
					},
				}
				new_ident = false
				continue
			}
		}
		if new_ident {
			iam.identities = append(iam.identities, &Identity{
				Name: key,
				Credentials: []*Credential{
					{
						AccessKey: api_access_key,
						SecretKey: api_secret_key,
					},
				},
				Actions: nil,
			})
		}
	}
	return nil
}
