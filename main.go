package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/harishduwadi/tlsConnection/db"
	"github.com/harishduwadi/tlsConnection/engine"

	"github.com/harishduwadi/tlsConnection/config"
	yaml "gopkg.in/yaml.v2"
)

func main() {

	yamlconf, err := readconfig()
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

	engine.Start(db, yamlconf.Dns, yamlconf.XmlFileDestination)

}

func readconfig() (*config.Yamlconfig, error) {

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
