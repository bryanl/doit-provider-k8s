package k8s

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/template"
	"github.com/bryanl/doit-provider-k8s/certauth"
	"github.com/digitalocean/godo"
)

var (
	nodeImage = "coreos-alpha"
	nodeSize  = "4gb"
)

// K8s builds a k8s installation.
type K8s struct {
	dir    string
	region string
	name   string
}

// New creates a K8s instance.
func New(name, region, dir string) (*K8s, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	return &K8s{
		name:   name,
		region: region,
		dir:    dir,
	}, nil
}

// Init initializes k8s.
func (k *K8s) Init() error {
	ca, err := certauth.New(k.dir)
	if err != nil {
		return fmt.Errorf("could not init ca: %v", err)
	}

	err = ca.CreateRoot()
	if err != nil {
		return fmt.Errorf("could not create root: %v", err)
	}

	err = ca.CreateAPIServerKeyPair("127.0.0.1")
	if err != nil {
		return fmt.Errorf("could not create api server key pair: %v", err)
	}

	err = ca.CreateWorkerKeyPair("worker.example.com", "172.17.0.5")
	if err != nil {
		return fmt.Errorf("could not create worker key pair: %v", err)
	}

	err = ca.CreateAdminKeyPair()
	if err != nil {
		return fmt.Errorf("could not create admin key pair: %v", err)
	}

	return nil
}

// CreateSSHKey creates a ssh key if one does not exist.
func (k *K8s) CreateSSHKey() (string, error) {
	privateKeyPath := filepath.Join(k.dir, "k8s.key")
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		log.Println("creating ssh key: ", privateKeyPath)
		cmd := exec.Command("ssh-keygen", "-t", "rsa", "-q", "-N", "", "-f", privateKeyPath)
		err := cmd.Run()
		if err != nil {
			return "", err
		}
	}

	cmd := exec.Command("ssh-keygen", "-E", "md5", "-lf", privateKeyPath)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(out))
	parts := strings.SplitN(fields[1], ":", 2)
	fingerprint := parts[1]
	log.Println("fingerprint is", fingerprint)

	doitOut, err := k.doit("ssh-key", "get", fingerprint)
	log.Println(doitOut)
	if err != nil {
		publicKeyPath := privateKeyPath + ".pub"
		log.Println("uploading key to api:", publicKeyPath)

		_, err = k.doit("ssh-key", "import", k.name, "--public-key-file", publicKeyPath)
		if err != nil {
			return "", fmt.Errorf("unable to upload public key: %v", err)
		}

		log.Println("key uploaded")

		return fingerprint, nil
	}

	log.Println("key existed in api")

	return fingerprint, nil
}

// ConfigureMaster configures the master node.
func (k *K8s) ConfigureMaster(sshFingerprint string) error {
	cloudConfigPath, err := k.prepareMasterCloudConfig()
	if err != nil {
		return err
	}
	defer func() {
		os.Remove(cloudConfigPath)
	}()

	name := fmt.Sprintf("cs-%s-master-%s", k.name, k.region)
	log.Printf("booting master: %s", name)

	out, err := k.doit("droplet", "create", name,
		"--output", "json",
		"--image", nodeImage,
		"--region", k.region,
		"--size", nodeSize,
		"--ssh-keys", sshFingerprint,
		"--user-data-file", cloudConfigPath,
		"--wait")
	if err != nil {
		return err
	}

	var droplets []godo.Droplet
	err = json.Unmarshal([]byte(out), &droplets)
	if err != nil {
		return err
	}

	if l := len(droplets); l != 1 {
		return fmt.Errorf("received unexpected number of droplets: %d", l)
	}

	masterIP := droplets[0].Networks.V4[0].IPAddress
	log.Printf("master ip is %s", masterIP)

	err = k.installMasterAuth(masterIP)
	if err != nil {
		return fmt.Errorf("unable to configure tls: %v", err)
	}

	return nil
}

func (k *K8s) prepareMasterCloudConfig() (string, error) {
	f, err := ioutil.TempFile("", "mcc")
	if err != nil {
		return "", err
	}

	t, err := template.New("cloud config").Parse(masterCloudConfig)
	if err != nil {
		return "", err
	}

	err = t.Execute(f, nil)
	if err != nil {
		return "", err
	}

	err = f.Close()
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

func (k *K8s) installMasterAuth(masterIP string) error {
	host := "core@" + masterIP
	stageDir := "/home/core/ssl"

	err := k.sshCmd(host, "mkdir", "-p", stageDir)
	if err != nil {
		return err
	}

	for _, f := range []string{"ca.pem", "apiserver.pem", "apiserver-key.pem", "admin.pem", "admin-key.pem"} {
		err = k.sshCopy(host, stageDir, f)
		if err != nil {
			return err
		}
	}

	return nil
}

func (k *K8s) sshCopy(host, remoteDir, name string) error {
	cmd := exec.Command("scp", "-o", "stricthostkeychecking=no",
		"-i", filepath.Join(k.dir, "k8s.key"),
		filepath.Join(k.dir, name),
		fmt.Sprintf("%s:%s/%s", host, remoteDir, name))
	log.Println(cmd.Args)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("unable to copy file: %s", string(out))
		return err
	}

	return nil
}

func (k *K8s) sshCmd(host string, args ...string) error {
	failCount := 0
	maxFailCount := 5

	for failCount < maxFailCount {
		sshArgs := []string{"-o", "stricthostkeychecking=no", "-i", filepath.Join(k.dir, "k8s.key"), host}
		for _, arg := range args {
			sshArgs = append(sshArgs, arg)
		}

		cmd := exec.Command("ssh", sshArgs...)
		log.Println(cmd.Args)
		out, err := cmd.Output()
		if err == nil {
			return nil
		}

		log.Printf("unable to run ssh command: %s", string(out))
		time.Sleep(15 * time.Second)
		failCount++
	}

	return fmt.Errorf("command failed %d times", maxFailCount)
}

func (k *K8s) doit(args ...string) (string, error) {
	args = append(args, "-o", "json")
	log.Println("running doit", args)
	cmd := exec.Command("doit", args...)
	out, err := cmd.Output()
	return string(out), err
}

//go:generate embed file -var masterCloudConfig -source cloud-config.yaml
var masterCloudConfig = "#cloud-config\n\ncoreos:\n  etcd2:\n    advertise-client-urls: https://$public_ipv4:2379,https://$public_ipv4:4001\n    listen-client-urls: https://0.0.0.0:2379,https://0.0.0.0:4001\n  flannel:\n    etcd_cafile: /home/core/ssl/ca.pem\n    etcd_certfile: /home/core/ssl/admin.pem\n    etcd_keyfile: /home/core/ssl/admin-key.pem\n  locksmith:\n    etcd_cafile: /home/core/ssl/ca.pem\n    etcd_certfile: /home/core/ssl/client.pem\n    etcd_keyfile: /home/core/ssl/client-key.pem\n  units:\n    - name: etcd2.service\n      command: start\n    - name: flanneld.service\n      drop-ins: \n      - name: 50-network-config.conf\n        content: |\n          [Service]\n          ExecStartPre=/usr/bin/etcdctl set /coreos.com/network/config '{ \"Network\": \"10.3.0.0/16\" }'\n      command: start\nwrite_files:\n  - path: /run/systemd/system/etcd2.service.d/30-certificates.conf\n    permissions: 0644\n    content: |\n      [Service]\n      # client environment variables\n      Environment=ETCD_CA_FILE=/home/core/ssl/ca.pem\n      Environment=ETCD_CERT_FILE=/home/core/ssl/apiserver.pem\n      Environment=ETCD_KEY_FILE=/home/core/ssl/apiserver-key.pem\n\n"
