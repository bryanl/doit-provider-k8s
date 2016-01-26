package main

import (
	"log"

	"github.com/bryanl/doit-provider-k8s/k8s"
)

func main() {
	k, err := k8s.New("tcluster", "nyc1", "/tmp/foobar")
	if err != nil {
		log.Fatalf("build cluster management instance: %v", err)
	}

	fingerprint, err := k.CreateSSHKey()
	if err != nil {
		log.Fatalf("creating ssh key: %v", err)
	}

	log.Printf("using %s as ssh key", fingerprint)

	err = k.Init()
	if err != nil {
		log.Fatalf("initializing k8s: %v", err)
	}

	err = k.ConfigureMaster(fingerprint)
	if err != nil {
		log.Fatalf("creating master: %v", err)
	}
}
