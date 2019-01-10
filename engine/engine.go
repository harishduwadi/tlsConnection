package engine

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/harishduwadi/tlsConnection/db"

	"github.com/harishduwadi/tlsConnection/config"
)

func Start(db *db.Dbmanager, DNS []string, xmlfiledestination string) {

	updateDNS := make(map[string][]string)

	for _, name := range DNS {
		ips, err := net.LookupHost(name)
		if err != nil {
			log.Println(err)
			continue
		}

		for _, ip := range ips {

			// Check if servername and ip pair needs updating from the DB
			update, err := needsUpdating(name, ip, db)
			if err != nil {
				log.Println(config.Error, err)
				return
			}

			if !update {
				log.Println("NO UPDATING NEEDED", name)
				continue
			}

			updateDNS[name] = append(updateDNS[name], ip)

			// For each entry that enters here marshal config to another file for the certbot to read

			// TODO Need to find a way to either make a new Configuration.xml or maybe just call the certbot function
			// Call certbot here to create a new certificate for the specific entry

			/* Checking all the certificate of the SAN domains; just to make sure*/
		}
	}

	checkAndUpdateDB(db, updateDNS)
}

func checkAndUpdateDB(db *db.Dbmanager, DNSWIP map[string][]string) {

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	for name, ips := range DNSWIP {

		for _, ip := range ips {

			// Check if servername and ip pair needs updating from the DB
			update, err := needsUpdating(name, ip, db)
			if err != nil {
				log.Println(config.Error, err)
				return
			}

			// Here if update is still needed then cerbot didn't properly create new certificate and deploy the certificate
			if update {
				log.Println(config.Error, "UPDATING NEEDED", name)
				continue
			}

			certificate, err := setUpConnection(conf, ip, "443", name)
			if err != nil {
				log.Println(err)
				continue
			}

			updateDB(name, ip, certificate, db)

		}
	}

}

func updateDB(name string, ip string, certificate *config.CertificateEntry, db *db.Dbmanager) {
	// TODO Need to add update function where we need to update the entry instead of keep on adding new entry
	err := db.AddCertificate(name, ip, certificate.Subject, certificate.SerialNumber, certificate.Validity, certificate.Issuer)
	if err != nil {
		log.Println(err)
		return
	}

	certificateid, err := db.GetCertificateID(name, ip, certificate.SerialNumber)
	if err != nil {
		log.Println(err)
		return
	}

	for _, sanname := range certificate.AlterDomains {
		err = db.AddSANEntries(sanname, certificateid)
		if err != nil {
			log.Println(err)
		}
	}
}

func needsUpdating(servername string, ip string, db *db.Dbmanager) (bool, error) {

	expireDate, err := db.GetExpireDate(servername, ip)
	if err != nil {
		return false, err
	}

	// TODO; what if the certificate expires when the program runs
	nextRunTime := time.Now().AddDate(0, 0, 7)
	if expireDate.Before(nextRunTime) {
		return true, nil
	}

	return false, nil
}

func setUpConnection(conf *tls.Config, ipaddr string, port string, serverName string) (*config.CertificateEntry, error) {
	log.Println("ADDED", serverName, "\t", ipaddr)
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
		Validity:     cert.NotAfter,
		AlterDomains: cert.DNSNames,
		Issuer:       cert.Issuer.CommonName,
	}

	return certificate, nil
}

/*
for _, str := range certificate.AlterDomains {
				addr, err := net.LookupHost(str)
				if err != nil {
					fmt.Println(err)
					continue
				}
				for _, ip2 := range addr {
					lowercertificate, err := setUpConnection(conf, ip2, "443", str)
					if err != nil {
						fmt.Println(err)
						continue
					}
					if certificate.SerialNumber == lowercertificate.SerialNumber {
						continue
					}
					err = db.Add(lowercertificate, str, ip2)
					if err != nil {
						fmt.Println(err)
						continue
					}
				}
			}
*/
