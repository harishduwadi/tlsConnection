package db

import (
	"database/sql"
	"errors"
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

func (db *Dbmanager) AddCertificateEntry(servername string, ip string, commonname string, serialnumber string, validity time.Time, issuer string) error {
	queryString := "Insert into certificates values(DEFAULT, $1, $2, $3, $4, $5, $6)"
	_, err := db.dbsql.Exec(queryString, servername, ip, commonname, serialnumber, validity, issuer)
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

func (db *Dbmanager) GetCertificateEntry(servername string, ip string) (int, error) {
	queryString := "Select id From certificates Where servername=$1 and ip=$2"
	result := db.dbsql.QueryRow(queryString, servername, ip)
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

func (db *Dbmanager) GetExpireDate(servername string, ip string) (time.Time, error) {
	queryString := "Select validity From certificates Where servername=$1 and ip=$2"
	result := db.dbsql.QueryRow(queryString, servername, ip)
	var expireDate time.Time
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
	queryString := "Select id From sanentries where name=$1 and certificateID=$2"
	result := db.dbsql.QueryRow(queryString, sanname, certificateID)
	var sanID int
	err := result.Scan(&sanID)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, errors.New("GetSANEntry " + err.Error())
	}
	return sanID, nil
}

func (db *Dbmanager) UpdateCertificateEntry(id int, commonname string, serialnumber string, validity time.Time, issuer string) error {
	queryString := "Update certificates set commonname=$1, serialnumber=$2, validity=$3, issuer=$4 where id=$5"
	_, err := db.dbsql.Exec(queryString, commonname, serialnumber, validity, issuer, id)
	if err != nil {
		return errors.New("UpdateCertificateEntry " + err.Error())
	}
	return nil
}

func (db *Dbmanager) Close() {
	db.dbsql.Close()
}
