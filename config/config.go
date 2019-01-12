package config

import (
	"time"
)

type DbConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"pass"`
	Dbname   string `yaml:"dbname"`
	Port     int    `yaml:"port"`
	Host     string `yaml:"host"`
}

type CertificateEntry struct {
	Subject      string
	SerialNumber string
	Validity     time.Time
	AlterDomains []string
	Issuer       string
}

type Yamlconfig struct {
	Dbconf             *DbConfig `yaml:"dbconf"`
	Dns                []string  `yaml:"dns"`
	Logfile            string    `yaml:"logfile"`
	XmlFileDestination string    `yaml:"xmlfiledestination"`
}

const (
	Error = "[ERROR]"
	Info  = "[INFO]"
)

type Opts struct {
	PopulateDB        bool `short:"p" long:"populateDB" description:"This is used when we want to add a new domain in the DB. Note: Domains List is taken from the Configuration.xml file"`
	CertbotController bool `short:"c" long:"controller" description:"This is used as the controller that checks the Db and updates, and sends the certificate to the respective end points as required"`
}
