package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/harishduwadi/tlsConnection/certbotmanager"
	"github.com/harishduwadi/tlsConnection/db"

	certbotconfig "github.com/harishduwadi/sfcertbot/config"
	"github.com/harishduwadi/tlsConnection/config"
	yaml "gopkg.in/yaml.v2"
)

func main() {

	yamlconf, err := readyamlconfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	certConfig := new(certbotconfig.Configuration)

	err = readxmlconfig(certConfig, yamlconf.XmlFileDestination)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	logfile, err := os.OpenFile(yamlconf.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer logfile.Close()

	log.SetOutput(logfile)

	db, err := db.New(yamlconf.Dbconf)
	if err != nil {
		log.Println(err)
		return
	}
	defer db.Close()

	opts, err := parseOpts()
	if err != nil {
		log.Println(err)
		return
	}

	// TODO need to add a new program type that will take care of the signal interupt and also make
	// the program a daemon
	certbotmanager.Start(db, certConfig, opts)

}

func parseOpts() (*config.Opts, error) {
	opt := new(config.Opts)
	_, err := flags.ParseArgs(opt, os.Args)
	if err != nil {
		return opt, err
	}
	return opt, nil
}

func readyamlconfig() (*config.Yamlconfig, error) {

	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}
	conf := new(config.Yamlconfig)

	err = yaml.Unmarshal(yamlFile, conf)
	if err != nil {
		return nil, err
	}

	return conf, nil
}

func readxmlconfig(config *certbotconfig.Configuration, configFileLocation string) error {
	xmlFile, err := ioutil.ReadFile(configFileLocation)
	if err != nil {
		log.Fatal("Error opening file:", err)
		return err
	}
	err = xml.Unmarshal(xmlFile, &config)
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil

}
