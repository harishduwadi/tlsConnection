package certbotmanager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/harishduwadi/tlsConnection/db"

	"github.com/harishduwadi/sfcertbot/certbot"
	"github.com/harishduwadi/sfcertbot/certificate"
	certbotconfig "github.com/harishduwadi/sfcertbot/config"
	"github.com/harishduwadi/tlsConnection/config"
)

func Start(db *db.Dbmanager, certConfig *certbotconfig.Configuration, opt *config.Opts) {
	switch {
	case opt.CertbotController:
		certbotController(db, certConfig)
	case opt.PopulateDB:
		populateDB(db, certConfig)
	default:
	}
}

func certbotController(db *db.Dbmanager, certConfig *certbotconfig.Configuration) {

	requestCertConfig := new(certbotconfig.Configuration)
	requestCertConfig.KeyFileName = certConfig.KeyFileName
	requestCertConfig.LetsEncryptUrl = certConfig.LetsEncryptUrl

	// Create a RSA key for the client (works fine)
	// certbot.Register(certConfig)

	// Get all the certificates that will expire in the next 7 days time in DB
	expiredDomains, err := db.GetAllExpiredCommonNames(time.Now().In(time.UTC).AddDate(0, 0, 7))
	if err != nil {
		log.Println(config.Error, err)
		return
	}

	// Get the certificate configuration for the expired domains
	for _, cert := range certConfig.Certificates {
		if _, ok := expiredDomains[cert.CommonName]; ok {
			requestCertConfig.Certificates = append(requestCertConfig.Certificates, cert)
		}
	}

	fmt.Println(requestCertConfig)

	certpackage := new(certificate.Certificate)
	acmeClient := certbot.CreateClient(requestCertConfig)

	// Create new certificate for all the expired domains
	for _, cert := range requestCertConfig.Certificates {
		certpackage.CertConfig = &cert
		certpackage.SetEnvironmentVariables()
		rawcert, rawpkey, err := certpackage.CreateValidCertificate(acmeClient)
		if err != nil {
			log.Fatal(err)
		}
		certpackage.CleanEnvironmentVariables()
		err = updateCertificate(db, rawcert, rawpkey)
		if err != nil {
			log.Fatal(err)
		}
		// gRPC here to agent in the endpoint
	}

}

// Weird thing is going on when adding the rawCert to the database <-- Continue here
func updateCertificate(db *db.Dbmanager, rawCert []byte, rawpKey []byte) error {
	block, _ := pem.Decode(rawCert)
	if block == nil {
		log.Fatal("Failed to parse the certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	serialNumberInHex := fmt.Sprintf("%x", certificate.SerialNumber)

	err = db.UpdateCertificateEntry(certificate.Subject.CommonName, serialNumberInHex, certificate.NotBefore, rawCert, rawpKey, certificate.Issuer.CommonName)
	if err != nil {
		return err
	}

	return nil
}

func populateDB(db *db.Dbmanager, certConfig *certbotconfig.Configuration) {

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Go through each certificate listed in the xml
	for _, cert := range certConfig.Certificates {

		// Get IP for the domain name
		ips, err := net.LookupHost(cert.CommonName)
		if err != nil {
			log.Println(err)
			continue
		}

		// Get the certificate currently used by the domain
		certificate, err := setUpConnection(conf, ips[0], "443", cert.CommonName)
		if err != nil {
			log.Println(err)
			continue
		}

		// Add entry to Certificate Table
		certificateID, err := addCertificateToDB(db, certificate)
		if err != nil {
			log.Println(err)
			return
		}
		// Add entry to the SANEntries table
		err = addSanEntriesToDB(db, cert.SubjectAlternativeNames, certificateID)
		if err != nil {
			log.Println(err)
			return
		}

		// Add entry to Endpoint table
		for _, ip := range ips {

			endpointID, err := addEndpointEntry(db, ip)
			if err != nil {
				log.Println(err)
				return
			}
			// Add entry to certificateendpoint table
			certendid, err := db.GetCertificateEndPointEntry(certificateID, endpointID)
			if err != nil {
				log.Println(err)
				return
			}
			if certendid != -1 {
				continue
			}
			err = db.AddCertificateEndPointEntry(certificateID, endpointID)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func addCertificateToDB(db *db.Dbmanager, certificate *config.CertificateEntry) (int, error) {
	certificateID, err := db.GetCertificateEntry(certificate.Subject)
	if err != nil {
		return -1, err
	}
	if certificateID == -1 {
		err = db.AddCertificateEntry(certificate.Subject, certificate.SerialNumber, certificate.Validity, nil, nil, certificate.Issuer)
		if err != nil {
			return -1, err
		}
		certificateID, err = db.GetCertificateEntry(certificate.Subject)
		if err != nil {
			return -1, err
		}
	}
	return certificateID, err
}

func addSanEntriesToDB(db *db.Dbmanager, sans []string, certificateID int) error {
	for _, sanname := range sans {
		sanID, err := db.GetSANEntry(sanname, certificateID)
		if err != nil {
			return err
		}
		if sanID != -1 {
			continue
		}
		err = db.AddSANEntry(sanname, certificateID)
		if err != nil {
			log.Println(err)
			return err
		}
	}
	return nil
}

func addEndpointEntry(db *db.Dbmanager, ip string) (int, error) {
	endpointID, err := db.GetEndPointEntry(ip)
	if err != nil {
		return -1, err
	}
	if endpointID != -1 {
		return endpointID, nil
	}
	err = db.AddEndPointEntry(ip)
	if err != nil {
		return -1, err
	}
	endpointID, err = db.GetEndPointEntry(ip)
	if err != nil {
		return -1, err
	}
	return endpointID, nil
}

func setUpConnection(conf *tls.Config, ipaddr string, port string, serverName string) (*config.CertificateEntry, error) {
	conf.ServerName = serverName
	conn, err := tls.Dial("tcp", ipaddr+":"+port, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		return nil, err
	}

	cert := conn.ConnectionState().PeerCertificates[0]

	serialNumberInHex := fmt.Sprintf("%x", cert.SerialNumber)

	certificate := &config.CertificateEntry{
		Subject:      cert.Subject.CommonName,
		SerialNumber: serialNumberInHex,
		Validity:     cert.NotAfter.In(time.UTC),
		AlterDomains: cert.DNSNames,
		Issuer:       cert.Issuer.CommonName,
	}

	return certificate, nil
}
