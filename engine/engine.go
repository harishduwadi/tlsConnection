package engine

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/harishduwadi/tlsConnection/db"

	certbotconfig "github.com/harishduwadi/sfcertbot/config"
	"github.com/harishduwadi/tlsConnection/config"
)

func Start(db *db.Dbmanager, certConfig *certbotconfig.Configuration) {

	updatedDNS := make(map[string][]string)

	// TODO: need to call the register function of the certbot

	for _, cert := range certConfig.Certificates {
		name := cert.CommonName

		// TODO wildcard entries isn't being covered in this list currently
		// TODO Need to remove the duplicate entries like digikey.enterprise and fe.enterprise
		// 		Duplicate in the sense they share same certificate -- wild card entries
		// 		Currently we have two wild-card entries *.supplyframe.com and *.enterprise-demo.supplyframe.com

		ips, err := net.LookupHost(name)
		if err != nil {
			log.Println(config.Error, err)
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
				log.Println("NO UPDATING NEEDED", name, ip)
				continue
			}

			updatedDNS[name] = append(updatedDNS[name], ip)

			// For each entry that enters here marshal config to another file for the certbot to read

			// TODO Need to find a way to either make a new Configuration.xml or maybe just call the certbot function
			// Call certbot here to create a new certificate for the specific entry

			/* Checking all the certificate of the SAN domains; just to make sure*/
		}
	}

	checkAndUpdateDB(db, updatedDNS)
}

func checkAndUpdateDB(db *db.Dbmanager, DNSANDIP map[string][]string) {

	fmt.Println(DNSANDIP)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	for name, ips := range DNSANDIP {

		for _, ip := range ips {

			certificate, err := setUpConnection(conf, ip, "443", name)
			if err != nil {
				log.Println(config.Error, err)
				continue
			}

			updateDB(name, ip, certificate, db)

			// Check if servername and ip pair has been updated in the DB
			update, err := needsUpdating(name, ip, db)
			if err != nil {
				log.Println(config.Error, err)
				return
			}

			// Here if update is still needed then cerbot didn't properly create new certificate and deploy the certificate
			if update {
				log.Println(config.Error, "UPDATING UNSUCCESSFUL", name, ip)
			}

		}
	}

}

func updateDB(name string, ip string, certificate *config.CertificateEntry, db *db.Dbmanager) {

	certificateid, err := db.GetCertificateEntry(name, ip)
	if err != nil {
		log.Println(err)
		return
	}

	if certificateid == -1 {
		err = db.AddCertificateEntry(name, ip, certificate.Subject, certificate.SerialNumber, certificate.Validity, certificate.Issuer)
	} else {
		err = db.UpdateCertificateEntry(certificateid, certificate.Subject, certificate.SerialNumber, certificate.Validity, certificate.Issuer)
	}
	if err != nil {
		log.Println(err)
		return
	}

	certificateid, err = db.GetCertificateEntry(name, ip)
	if err != nil {
		log.Println(err)
		return
	}

	for _, sanname := range certificate.AlterDomains {
		sanID, err := db.GetSANEntry(sanname, certificateid)
		if err != nil {
			log.Println(err)
			continue
		}
		if sanID == -1 {
			continue
		}
		err = db.AddSANEntry(sanname, certificateid)
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
	nextRunTime := time.Now().In(time.UTC).AddDate(0, 0, 7)

	// Note: expireDate is always in UTC(GMT) timezone
	if expireDate.Before(nextRunTime) {
		return true, nil
	}

	return false, nil
}

func setUpConnection(conf *tls.Config, ipaddr string, port string, serverName string) (*config.CertificateEntry, error) {
	log.Println("ADDING", serverName, ipaddr)
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
