est-client-go
=================

EST client - RFC 7030

```go
package main

import (
	"fmt"
    "os"

	"github.com/laurentluce/est-client-go"
)

func main() {

    // EST server certificate
    file, _ := os.Open("server.pem")
    data := make([]byte, 2048)
    count, _ := file.Read(data)

    // EST client
	client := est.Client{
                UrlPrefix: "https://testrfc7030.cisco.com:8443",
                Username: "estuser",
                Password: "estpwd",
                ServerCert: data[:count]}

    // Get EST server CA certs.
    content, err := client.CaCerts()

    // Create CSR
    commonName := "Test"
    country := "FR"
    state := "Guadeloupe"
    city := "Anse Bananier"
    organization := "Relax"
    organizationalUnit := "Secret"
    emailAddress := "test@example.com"
    priv, csr, err := est.CreateCsr(commonName, country, state, city,
                                    organization, organizationalUnit,
                                    emailAddress)

    // Enroll using CSR.
    content, err = client.SimpleEnroll(csr)

    // Reenroll using CSR.
    content, err = client.SimpleReenroll(csr, nil, nil)
}
```
