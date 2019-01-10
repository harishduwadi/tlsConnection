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
