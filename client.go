package est

import (
)

// Client represents and EST client.
type Client struct {
    URLPrefix string
    Username string
    Password string
    ServerCert []byte
}

// CaCerts issues an EST GET /cacerts request.
// Return CA certs in PEM format.
func (c *Client) CaCerts() ([]byte, error) {
	url := c.URLPrefix + "/.well-known/est/cacerts"
	content, err := Get(url, nil, c.ServerCert)
    if err != nil {
		return nil, err
	}

    p, err := PKCS7ToPEMOpenSSL(content)
    if err != nil {
		return nil, err
	}

    return p, err
}

// SimpleEnroll issues an EST POST /simpleenroll request.
// Takes a CSR in PEM format and returns the signed cert in PEM format.
func (c *Client) SimpleEnroll(csr []byte) ([]byte, error) {
	url := c.URLPrefix + "/.well-known/est/simpleenroll"
    headers := map[string]string{
        "Content-Type": "application/pkcs10",
    }

	content, err := Post(url, csr, headers, c.Username, c.Password,
                         nil, nil, c.ServerCert)
    if err != nil {
		return nil, err
	}

    p, err := PKCS7ToPEMOpenSSL(content)
    if err != nil {
		return nil, err
	}

    return p, err
}

// SimpleReenroll issues an EST POST /simplereenroll request.
// Takes a CSR in PEM format and returns the signed cert in PEM format.
// You can also pass a client cert/key for authentication.
func (c *Client) SimpleReenroll(csr []byte, clientCert []byte,
                                clientKey []byte) ([]byte, error) {
	url := c.URLPrefix + "/.well-known/est/simplereenroll"
    headers := map[string]string{
        "Content-Type": "application/pkcs10",
    }

    content, err := Post(url, csr, headers, c.Username, c.Password,
                         clientCert, clientKey, c.ServerCert)
    if err != nil {
		return nil, err
	}

    p, err := PKCS7ToPEMOpenSSL(content)
    if err != nil {
		return nil, err
	}

    return p, err
}
