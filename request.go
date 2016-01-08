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

func Get(url string, headers map[string]string,
         serverCert []byte) ([]byte, error) {

	return Send("GET", url, nil, headers, "", "", nil, nil, serverCert)
}

func Post(url string, data []byte, headers map[string]string,
          username string, password string, clientCert []byte,
          clientKey []byte, serverCert []byte) ([]byte, error) {

	return Send("POST", url, data, headers, username, password,
                clientCert, clientKey, serverCert)
}


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
        body_dec := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
        l, err := base64.StdEncoding.Decode(body_dec, body)
        if err != nil {
            return nil, err
        }

        return body_dec[:l], nil

    }

	return body, nil
}
