package est

import (
	"io/ioutil"
	"net/http"
)

func Get(url string, headers map[string]string, retries int, timeout int,
		 verify bool, cert []byte) ([]byte, error) {

	return Send("GET", url, nil, headers, "", "", retries, timeout,
			    verify, cert)
}

func Send(method string, url string, data []byte, headers map[string]string,
		  username string, password string, retries int, timeout int,
		  verify bool, cert []byte) ([]byte, error) {

	client := &http.Client{}

	req, err := http.NewRequest(method, url, nil)
    if err != nil {
		return nil, err
	}
    // req.Header.Set("User-Agent", "Golang Spider Bot v. 3.0")

    resp, err := client.Do(req)
    if err != nil {
		return nil, err
	}

    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
		return nil, err
    }

	return body, nil
}
