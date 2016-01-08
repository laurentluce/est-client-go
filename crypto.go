package est

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"
    "io/ioutil"
    "os/exec"
)

// Convert PKCS#7 cert to PEM format using openssl.
func PKCS7ToPEMOpenSSL(data []byte) ([]byte, error) {

    informs := []string{"PEM", "DER"}
    for _, inform := range informs {
        cmd := exec.Command("openssl", "pkcs7", "-inform", inform, "-outform",
                            "PEM", "-print_certs")

        in, _ := cmd.StdinPipe()
        out, _ := cmd.StdoutPipe()
        err, _ := cmd.StderrPipe()
        cmd.Start()
        in.Write(data)
        in.Close()
        cmdOut, _ := ioutil.ReadAll(out)
        cmdErr, _ := ioutil.ReadAll(err)
        if len(cmdErr) == 0 {
            return cmdOut, nil
        }
        cmd.Wait()
    }

    err := errors.New("PKCS7 type not supported.")
    return nil, err
}

// Create CSR, return private key and CSR in PEM format.
func CreateCsr(commonName string, country string, state string, city string,
               organization string, organizationalUnit string,
               emailAddress string) ([]byte, []byte, error) {

    priv, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, err
    }

    template := x509.CertificateRequest{
            Subject: pkix.Name{
                CommonName:         commonName,
                Country:            []string{country},
                Province:           []string{state},
                Locality:           []string{city},
                Organization:       []string{organization},
                OrganizationalUnit: []string{organizationalUnit},
            },
            SignatureAlgorithm: x509.SHA256WithRSA,
            EmailAddresses:     []string{emailAddress},
    }

    random := rand.Reader
    csrBytes, err := x509.CreateCertificateRequest(random, &template, priv)
    if err != nil {
        return nil, nil, err
    }

    block := pem.Block{
        Type: "CERTIFICATE REQUEST",
        Bytes: csrBytes,
    }
    certPem := pem.EncodeToMemory(&block)

    block = pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(priv),
    }
    privPem := pem.EncodeToMemory(&block)

    return privPem, certPem, nil
}

