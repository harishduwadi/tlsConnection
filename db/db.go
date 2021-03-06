package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/harishduwadi/tlsConnection/config"

	_ "github.com/lib/pq"
)

type Dbmanager struct {
	dbsql *sql.DB
}

func New(config *config.DbConfig) (*Dbmanager, error) {
	connectStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", config.Host, config.Port, config.User, config.Password, config.Dbname)

	db, err := sql.Open("postgres", connectStr)
	if err != nil {
		return nil, err
	}
	dbm := new(Dbmanager)
	dbm.dbsql = db
	return dbm, nil
}

func (db *Dbmanager) AddCertificateEntry(commonname string, serialnumber string, validity time.Time, rawCert []byte, issuer string, keyid int) error {
	queryString := "Insert into certificates values(DEFAULT, $1, $2, $3, $4, $5, $6)"
	_, err := db.dbsql.Exec(queryString, commonname, serialnumber, validity, rawCert, issuer, keyid)
	if err != nil {
		return errors.New("AddCertificateEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) AddSANEntry(sanname string, certificateID int) error {
	queryString := "Insert into sanentries Values(DEFAULT, $1, $2)"
	_, err := db.dbsql.Exec(queryString, sanname, certificateID)
	if err != nil {
		return errors.New("AddSANEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) AddEndPointEntry(ip string) error {
	queryString := "Insert Into endpoints Values(DEFAULT, $1)"
	_, err := db.dbsql.Exec(queryString, ip)
	if err != nil {
		return errors.New("AddEndPointEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) AddCertificateEndPointEntry(certificateID int, endpointID int) error {
	queryString := "Insert Into certificateendpoint values(DEFAULT, $1, $2)"
	_, err := db.dbsql.Exec(queryString, certificateID, endpointID)
	if err != nil {
		return errors.New("AddCertificateEndPointEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) AddUpdateListEntry(certificateID int, endpointID int) error {
	queryString := "Insert Into updateList values(DEFAULT, $1, $2, DEFAULT)"
	_, err := db.dbsql.Exec(queryString, certificateID, endpointID)
	if err != nil {
		return errors.New("AddUpdateListEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) GetCertificateEntry(commonname string) (int, error) {
	queryString := "Select id From certificates Where commonname=$1"
	result := db.dbsql.QueryRow(queryString, commonname)
	var certificateId int
	err := result.Scan(&certificateId)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, errors.New("GetCertificateEntry " + err.Error())
	}
	return certificateId, nil
}

func (db *Dbmanager) GetAllExpiredCommonNames(curTime time.Time) (map[string]string, error) {
	expiredDomains := make(map[string]string)

	queryString := "Select commonname From certificates Where validity<$1"
	rows, err := db.dbsql.Query(queryString, curTime)
	if err != nil {
		return expiredDomains, errors.New("GetAllExpiredCommonNames " + err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var domain string
		err := rows.Scan(&domain)
		if err != nil {
			return expiredDomains, errors.New("GetAllExpiredCommonNames " + err.Error())
		}
		expiredDomains[domain] = ""
	}
	return expiredDomains, nil
}

func (db *Dbmanager) GetExpireDate(commonname string, ip string) (time.Time, error) {
	var expireDate time.Time
	queryString := "Select validity From certificates Where commonname=$1 and ip=$2"
	result := db.dbsql.QueryRow(queryString, commonname, ip)
	err := result.Scan(&expireDate)
	if err == sql.ErrNoRows {
		return time.Now(), nil
	}
	if err != nil {
		return time.Now(), errors.New("GetExpireDate " + err.Error())
	}
	return expireDate, nil
}

func (db *Dbmanager) GetSANEntry(sanname string, certificateID int) (int, error) {
	var sanID int
	queryString := "Select id From sanentries where name=$1 and certificateID=$2"
	result := db.dbsql.QueryRow(queryString, sanname, certificateID)
	err := result.Scan(&sanID)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, errors.New("GetSANEntry " + err.Error())
	}
	return sanID, nil
}

func (db *Dbmanager) GetEndPointEntry(ip string) (int, error) {
	var ipaddrid int
	queryString := "Select id From Endpoints Where ip=$1"
	row := db.dbsql.QueryRow(queryString, ip)
	err := row.Scan(&ipaddrid)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, errors.New("GetEndPointEntry " + err.Error())
	}
	return ipaddrid, nil
}

func (db *Dbmanager) GetCertificateEndPointEntry(certificateID int, endpointid int) (int, error) {
	var id int
	queryString := "Select id From CertificateEndPoint Where certificateId=$1 and endpointID=$2"
	row := db.dbsql.QueryRow(queryString, certificateID, endpointid)
	err := row.Scan(&id)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, errors.New("GetCertificateEndPointEntry " + err.Error())
	}
	return id, nil
}
func (db *Dbmanager) GetCertificateEntriesForEndPoint(endpoint string) ([]config.CertificateEntry, error) {
	queryString := `Select c.commonname, c.serialnumber, c.validity, c.issuer
					From certificates c join (
						Select *
						From endpoints join certificateendpoint on endpoints.id=certificateendpoint.endpointid
						Where ip=$1
					) AS ED
					on c.id = ED.certificateid`

	results, err := db.dbsql.Query(queryString, endpoint)
	if err != nil {
		return nil, errors.New("GetStateOfEndPoint " + err.Error())
	}

	var certificateEntries []config.CertificateEntry

	for results.Next() {

		var name, sn, iss string
		var exp time.Time

		err = results.Scan(&name, &sn, &exp, &iss)
		if err != nil {
			log.Println("Parsing Error in GetStateOfEndPoint")
			continue
		}

		certificateEntries = append(certificateEntries, config.CertificateEntry{
			Subject:      name,
			SerialNumber: sn,
			Validity:     exp,
			Issuer:       iss,
		})
	}

	return certificateEntries, nil
}

func (db *Dbmanager) AddKeyEntry(apikey string, apikeyvarname string, apisecret string, apisecretvarname string, dnsprovider string) error {
	queryString := "Insert into keys values(DEFAULT, $1, $2, $3, $4, $5)"
	_, err := db.dbsql.Exec(queryString, apikeyvarname, apikey, apisecretvarname, apisecret, dnsprovider)
	if err != nil {
		return errors.New("AddKeyEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) GetKeyId(apikey string, apisecret string) (int, error) {
	querString := "Select id From keys Where apikey=$1 and apisecret=$2"
	row := db.dbsql.QueryRow(querString, apikey, apisecret)
	var id int
	err := row.Scan(&id)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, errors.New("GetKeyId " + err.Error())
	}
	return id, nil
}

// UpdateCertificateEntry is used to update already existed certificate entry in the certificates table
func (db *Dbmanager) UpdateCertificateEntry(commonname string, serialnumber string, validity time.Time, rawfile []byte, issuer string) error {
	queryString := "Update certificates set serialnumber=$1, validity=$2, rawfile=$3, issuer=$4 where commonname=$5"
	_, err := db.dbsql.Exec(queryString, serialnumber, validity, rawfile, issuer, commonname)
	if err != nil {
		return errors.New("UpdateCertificateEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) Close() {
	db.dbsql.Close()
}
