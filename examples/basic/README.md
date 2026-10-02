# PKIX example

This example uses the public `ecosystem::x509` and `ecosystem::asn1` packages through the root manifest. It round-trips a distinguished name and a typed extension without using a certificate verifier.

Run `(cd ../verification && just ecosystem-test x509)` from the library root.

This example shares the library root manifest and its dependencies. From the library root, run `goml verify --example basic` to build and test it as an independent downstream module.
