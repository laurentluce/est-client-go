est-client-go
=================

EST client - RFC 7030

```go
// EST client.  Username and password will be used for basic auth.
// serverCert contains the EST server certificate in PEM format.
client := est.Client{
            URLPrefix: "https://testrfc7030.cisco.com:8443",
            Username: "estuser",
            Password: "estpwd",
            ServerCert: serverCert}

// Get EST server CA certs in PEM format.
caCerts, err := client.CaCerts()

// Create CSR.  CreateCsr returns the CSR and the private key generated
// in PEM format.
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

// Enroll using the CSR.  SimpleEnroll returns the signed cert in PEM format.
cert, err = client.SimpleEnroll(csr)

// Reenroll using the CSR.
cert, err = client.SimpleReenroll(csr, nil, nil)

// Reenroll using the CSR and the client cert/key for authentication.
cert, err = client.SimpleReenroll(csr, cert, priv)
```
