package est

import (
)

type Client struct {
    UrlPrefix string
    Username string
    Password string
    ImplicitTrustAnchorCertPath string
	Retries int
	Timeout int
	Verify bool
}

func (c *Client) CaCerts() ([]byte, error) {
	url := c.UrlPrefix + "/cacerts"
	content, err := Get(url, nil, c.Retries, c.Timeout, c.Verify, nil)
    if err != nil {
		return nil, err
	}

    return content, err
}

func (c *Client) SetAuth(username string, password string) (error) {
	return nil
}

func (c *Client) SimpleEnroll(csr []byte) ([]byte, error) {
	return nil, nil
}

func (c *Client) SimpleReenroll(csr []byte, cert []byte) ([]byte, error) {
	return nil, nil
}
