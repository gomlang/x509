package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
)

func main() {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	u, _ := url.Parse("https://example.com/path")
	t := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.com", "example.com"}, EmailAddresses: []string{"user@example.com"}, URIs: []*url.URL{u}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("2001:db8::1")}}
	der, e := x509.CreateCertificate(rand.Reader, t, t, key.Public(), key)
	if e != nil {
		panic(e)
	}
	c, e := x509.ParseCertificate(der)
	if e != nil {
		panic(e)
	}
	f, _ := os.Create("pkix/tests/san_reference_test.goml")
	defer f.Close()
	fmt.Fprintln(f, "package tests;\nuse ecosystem::asn1;\nuse ecosystem::x509::pkix::{SubjectAltName, GeneralName};\nuse std::testing;\n#[test]\nfn go_x509_san_der() -> () {")
	for _, e := range c.Extensions {
		if e.Id.String() == "2.5.29.17" {
			fmt.Fprint(f, "let der = b\"")
			for _, b := range e.Value {
				fmt.Fprintf(f, "\\x%02x", b)
			}
			fmt.Fprintln(f, "\";\nlet san = testing::expect_ok(SubjectAltName::from_der(der.as_slice(), asn1::Limits::standard()), \"Go SAN DER\");\ntesting::assert_eq(san.names.len(), 6);\ntesting::assert(san.names[0] == GeneralName::Dns(\"example.com\"));\ntesting::assert(san.names[2] == GeneralName::Rfc822(\"user@example.com\"));\ntesting::assert(san.names[3] == GeneralName::Ip(b\"\\x7f\\x00\\x00\\x01\"));\ntesting::assert(testing::expect_ok(san.to_der(asn1::Limits::standard()), \"encode\") == der);")
		}
	}
	fmt.Fprintln(f, "}")
}
