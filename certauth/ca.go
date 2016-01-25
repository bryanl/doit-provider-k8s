package certauth

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/alecthomas/template"
)

const defaultServiceIP = "10.3.0.1"

// CA is a certificate authority.
type CA struct {
	// Dir is the path where certs and keys will be generated
	dir string

	// ServiceIP is the IP address of the k8s api service.
	serviceIP string

	// Verbose mode displays command output
	verbose bool
}

// New creates a CA.
func New(dir string, opts ...func(*CA)) (*CA, error) {
	ca := &CA{
		dir:       dir,
		serviceIP: defaultServiceIP,
		verbose:   false,
	}

	for _, opt := range opts {
		opt(ca)
	}

	return ca, nil
}

// IsVerbose sets verbose mode.
func IsVerbose() func(*CA) {
	return func(ca *CA) {
		ca.verbose = true
	}
}

// CreateRoot creates a certificate authority that will be used to sign
// additional certificates.
func (ca *CA) CreateRoot() error {
	err := ca.openssl("genrsa", "-out", "ca-key.pem", "2048")
	if err != nil {
		return err
	}

	return ca.openssl("req", "-x509", "-new", "-nodes", "-key",
		"ca-key.pem", "-days", "10000", "-out", "ca.pem", "-subj",
		"/CN=kube-ca")
}

// CreateAPIServerKeyPair creates a keypair for the api server.
func (ca *CA) CreateAPIServerKeyPair(masterIP string) error {
	p := filepath.Join(ca.dir, "openssl.cnf")
	f, err := os.Create(p)
	if err != nil {
		return err
	}

	t, err := template.New("openssl config").Parse(opensslConfig)
	if err != nil {
		return err
	}

	args := map[string]interface{}{
		"ServiceIP":  ca.serviceIP,
		"MasterHost": masterIP,
	}

	err = t.Execute(f, args)
	if err != nil {
		return err
	}

	err = ca.openssl("genrsa", "-out", "apiserver-key.pem", "2048")
	if err != nil {
		return err
	}

	err = ca.openssl("req", "-new", "-key", "apiserver-key.pem", "-out", "apiserver.csr",
		"-subj", "/CN=kube-apiserver", "-config", "openssl.cnf")
	if err != nil {
		return err
	}

	return ca.openssl("x509", "-req", "-in", "apiserver.csr", "-CA", "ca.pem",
		"-CAkey", "ca-key.pem", "-CAcreateserial", "-out", "apiserver.pem",
		"-days", "365", "-extensions", "v3_req", "-extfile", "openssl.cnf")
}

// CreateWorkerKeyPair creates key pairs for workers.
func (ca *CA) CreateWorkerKeyPair(workerFQDN, workerIP string) error {
	p := filepath.Join(ca.dir, "worker-openssl.cnf")
	f, err := os.Create(p)
	if err != nil {
		return err
	}

	t, err := template.New("worker openssl config").Parse(workerOpensslConfig)
	if err != nil {
		return err
	}

	args := map[string]interface{}{
		"WorkerIP": workerIP,
	}

	err = t.Execute(f, args)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s-worker-key.pem", workerFQDN)
	csr := fmt.Sprintf("%s-worker.csr", workerFQDN)
	crt := fmt.Sprintf("%s-worker.pem", workerFQDN)

	err = ca.openssl("genrsa", "-out", key, "2048")
	if err != nil {
		return err
	}

	err = ca.openssl("req", "-new", "-key", key,
		"-out", csr, "-subj", "/CN=${WORKER_FQDN}",
		"-config", "worker-openssl.cnf")
	if err != nil {
		return err
	}

	return ca.openssl("x509", "-req", "-in", csr,
		"-CA", "ca.pem", "-CAkey", "ca-key.pem", "-CAcreateserial",
		"-out", crt, "-days", "365",
		"-extensions", "v3_req", "-extfile", "worker-openssl.cnf")
}

// CreateAdminKeyPair creates an admin key pair
func (ca *CA) CreateAdminKeyPair() error {
	err := ca.openssl("genrsa", "-out", "admin-key.pem", "2048")
	if err != nil {
		return err
	}

	err = ca.openssl("req", "-new", "-key", "admin-key.pem",
		"-out", "admin.csr", "-subj", "/CN=kube-admin")
	if err != nil {
		return err
	}

	return ca.openssl("x509", "-req", "-in", "admin.csr", "-CA", "ca.pem",
		"-CAkey", "ca-key.pem", "-CAcreateserial",
		"-out", "admin.pem", "-days", "365")
}

func (ca *CA) openssl(args ...string) error {
	cmd := exec.Command("openssl", args...)
	cmd.Dir = ca.dir

	out, err := cmd.CombinedOutput()

	if ca.verbose {
		fmt.Println(string(out))
	}

	return err
}

//go:generate embed file -var opensslConfig -source openssl.cnf
var opensslConfig = "[req]\nreq_extensions = v3_req\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n[ v3_req ]\nbasicConstraints = CA:FALSE\nkeyUsage = nonRepudiation, digitalSignature, keyEncipherment\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = kubernetes\nDNS.2 = kubernetes.default\nIP.1 = {{.ServiceIP}}\nIP.2 = {{.MasterHost}}\n"

//go:generate embed file -var workerOpensslConfig -source worker-openssl.cnf
var workerOpensslConfig = "[req]\nreq_extensions = v3_req\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n[v3_req]\nbasicConstraints = CA:FALSE\nkeyUsage = nonRepudiation, digitalSignature, keyEncipherment\nsubjectAltName = @alt_names\n[alt_names]\nIP.1 = {{.WorkerIP}}\n"
