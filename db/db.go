package db

import (
	"database/sql"
	"fmt"
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

func (db *Dbmanager) AddCertificate(servername string, ip string, commonname string, serialnumber string, validity time.Time, issuer string) error {
	queryString := "Insert into certificates values(DEFAULT, $1, $2, $3, $4, $5, $6)"
	_, err := db.dbsql.Exec(queryString, servername, ip, commonname, serialnumber, validity, issuer)
	return err
}

func (db *Dbmanager) AddSANEntries(sanname string, certificateID int) error {

	queryString := "Insert into sanentries Values(DEFAULT, $1, $2)"
	_, err := db.dbsql.Exec(queryString, sanname, certificateID)
	return err
}

func (db *Dbmanager) GetCertificateID(servername string, ip string, serialnumber string) (int, error) {
	queryString := "Select id From certificates Where servername=$1 and ip=$2 and serialnumber=$3"
	result := db.dbsql.QueryRow(queryString, servername, ip, serialnumber)
	var id int
	err := result.Scan(&id)
	return id, err
}

func (db *Dbmanager) GetExpireDate(servername string, ip string) (time.Time, error) {
	queryString := "Select validity From certificates Where servername=$1 and ip=$2"
	result := db.dbsql.QueryRow(queryString, servername, ip)
	var expireDate time.Time
	err := result.Scan(expireDate)
	if err == sql.ErrNoRows {
		return time.Now(), nil
	}
	if err != nil {
		return time.Now(), err
	}
	return expireDate, nil
}

func (db *Dbmanager) Close() {
	db.dbsql.Close()
}
