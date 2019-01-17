package certbotmanager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// time out for setting up a connection
const timeOut = 10

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

	// Create a RSA key for the client (works fine)
	certbot.Register(certConfig)

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

		err = addToUpdateListTable(db, cert)
		if err != nil {
			log.Println(err)
		}
	}

}

func populateDB(db *db.Dbmanager, certConfig *certbotconfig.Configuration) {

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Go through each certificate listed in the xml
	for _, xmlCert := range certConfig.Certificates {

		// Get IP for the domain name
		ips := xmlCert.Endpoints

		log.Println("Setting up connection to host", xmlCert.CommonName, "in ip", ips[0])

		// Get the certificate currently used by the domain;
		// TODO: Here if there is no certificate, should return error.
		// Instead of just logging the error, might need to create a new entry with time that is already expired
		certificate, err := setUpConnection(conf, ips[0], "443", xmlCert.CommonName)
		if err != nil {
			log.Println(err)
			continue
		}

		// Change the SAN entries to the one listed in the xml file
		// TODO: Removing from DB is not properly set yet
		certificate.AlterDomains = xmlCert.SubjectAlternativeNames

		log.Println("Adding Entries to DB")

		// Add entry to Certificate Table
		certificateID, err := updateCertificateTable(db, certificate)
		if err != nil {
			log.Println(err)
			return
		}
		// Add entry to the SANEntries table
		err = updateSANTable(db, xmlCert.SubjectAlternativeNames, certificateID)
		if err != nil {
			log.Println(err)
			return
		}

		// Add entries to Endpoint table
		for _, ip := range ips {

			endpointID, err := updateEndPointTable(db, ip)
			if err != nil {
				log.Println(err)
				return
			}

			// Check if there already exists a relation
			certendid, err := db.GetCertificateEndPointEntry(certificateID, endpointID)
			if err != nil {
				log.Println(err)
				return
			}
			if certendid != -1 {
				continue
			}

			// Add entry to certificateendpoint table
			err = db.AddCertificateEndPointEntry(certificateID, endpointID)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}

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
	log.Println(certificate.Subject.CommonName, serialNumberInHex, certificate.NotBefore)
	err = db.UpdateCertificateEntry(certificate.Subject.CommonName, serialNumberInHex, certificate.NotBefore, rawCert, rawpKey, certificate.Issuer.CommonName)
	if err != nil {
		return err
	}

	return nil
}

func addToUpdateListTable(db *db.Dbmanager, cert certbotconfig.CertificateConfiguration) error {

	certID, err := db.GetCertificateEntry(cert.CommonName)
	if err != nil || certID == -1 {
		return err
	}

	for _, ip := range cert.Endpoints {
		endpointID, err := db.GetEndPointEntry(ip)
		if err != nil || endpointID == -1 {
			return err
		}

		err = db.AddUpdateListEntry(certID, endpointID)
		if err != nil {
			return err
		}
	}

	return nil
}

func updateCertificateTable(db *db.Dbmanager, certificate *config.CertificateEntry) (int, error) {
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

func updateSANTable(db *db.Dbmanager, sans []string, certificateID int) error {
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

func updateEndPointTable(db *db.Dbmanager, ip string) (int, error) {
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

	// Set up a connection with a time-out
	conn, err := net.DialTimeout("tcp", ipaddr+":"+port, timeOut*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, conf)
	defer tlsConn.Close()

	log.Println("Performing Handshake with host completed")

	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	log.Println("HandShake with host completed")

	cert := tlsConn.ConnectionState().PeerCertificates[0]

	if cert == nil {
		return nil, errors.New("No certificate for " + serverName + " with address " + ipaddr)
	}

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
