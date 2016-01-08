package est

import (
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "errors"
	"io/ioutil"
	"net/http"
)

// Get issues an HTTP GET request.
// Returns the response body.
func Get(url string, headers map[string]string,
         serverCert []byte) ([]byte, error) {

	return Send("GET", url, nil, headers, "", "", nil, nil, serverCert)
}

// Post issues an HTTP POST request.
// username and password are used for basic auth.
// clientKey and clientCert are used for TLS auth.
// Returns the response body.
func Post(url string, data []byte, headers map[string]string,
          username string, password string, clientCert []byte,
          clientKey []byte, serverCert []byte) ([]byte, error) {

	return Send("POST", url, data, headers, username, password,
                clientCert, clientKey, serverCert)
}

// Send issues an HTTP request.  Returns the body.
func Send(method string, url string, data []byte, headers map[string]string,
		  username string, password string,
		  clientCert []byte,
          clientKey []byte, serverCert []byte) ([]byte, error) {

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(serverCert)

    tlsConfig := tls.Config{
        RootCAs:      caCertPool,
    }

    if clientCert != nil && clientKey != nil {
        cert, err := tls.X509KeyPair(clientCert, clientKey)
        if err != nil {
            return nil, err
        }
        tlsConfig.Certificates = []tls.Certificate{cert}
    }

    tlsConfig.BuildNameToCertificate()

    tr := &http.Transport{
        TLSClientConfig:    &tlsConfig,
    }

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, bytes.NewReader(data))
    if err != nil {
		return nil, err
	}

    if username != "" && password != "" {
        req.SetBasicAuth(username, password)
    }

    for key, value := range headers {
        req.Header.Set(key, value)
    }

    resp, err := client.Do(req)
    if err != nil {
		return nil, err
	}

    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
		return nil, err
    }

    if resp.StatusCode != 200 {
        err := errors.New(
            "Request error: " + resp.Status + " - " + string(body[:]))
        return nil, err
    }

    encoding := resp.Header.Get("Content-Transfer-Encoding")
    prefix := []byte{'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N'}
    if encoding == "base64" && !bytes.HasPrefix(body, prefix) {
        bodyDec := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
        l, err := base64.StdEncoding.Decode(bodyDec, body)
        if err != nil {
            return nil, err
        }

        return bodyDec[:l], nil

    }

	return body, nil
}
