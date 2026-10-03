# PKIX data structures

`ecosystem::x509::pkix` implements the DER data structures for distinguished names, object identifiers, extensions, and algorithm identifiers described by [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1). It depends on `ecosystem::asn1` for bounded, canonical tag/length parsing, OID encoding, and explicit typed schemas. It does not parse complete certificates, verify signatures or chains, choose trusted roots, or implement TLS.

`Name` preserves the ordered sequence of RDNs and every multi-valued RDN's SET members. `Name::to_der` sorts each SET by the complete encoded DER element, as DER requires; `Name::from_der` rejects unsorted SETs. A `Name` may be empty because RFC 5280 permits an empty subject with a critical subject alternative name; applications must apply issuer and subject profile rules in their own certificate context. Attributes carry OID arcs and a `DirectoryValue`. UTF8String, PrintableString, IA5String, BMPString, and UniversalString are decoded to validated GoML strings. Legacy TeletexString bytes and unknown tag values are retained explicitly for round trips; they are not silently reinterpreted as UTF-8. Named OID helpers cover common name attributes, basic constraints, key usage, and subject alternative names.

`BasicConstraints { ca, path_length }` provides typed DER encoding and decoding
for [RFC 5280 section 4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9).
`to_der` omits the default false CA flag; `from_der` rejects explicit false,
negative path lengths, a path length without `ca: true`, incorrect field order
and extra fields. `None` means unconstrained; `Some(0)` is a real zero constraint.
Path lengths are bounded to nonnegative `i64` values. Use the returned DER as
`Extension.value_der` with `basic_constraints_oid()`. The caller still enforces
certificate context, key usage, criticality and chain path-length semantics.

`KeyUsage` exposes all nine [RFC 5280 key-usage flags](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3):
`digital_signature`, `content_commitment`, `key_encipherment`, `data_encipherment`,
`key_agreement`, `key_cert_sign`, `crl_sign`, `encipher_only`, and `decipher_only`.
Start from `KeyUsage::new()` and set flags with a struct update. `to_der` encodes a
canonical named BIT STRING; `from_der` rejects unknown bits, all-zero values,
nonzero padding and trailing zero bits. At least one flag must be set when
encoding. Use `key_usage_oid()` and `Extension.value_der` to carry the value.
Algorithm-specific flag combinations, CA consistency and trust remain caller
policy; this type does not reject combinations the RFC leaves unrestricted.

`ExtendedKeyUsage { purposes }` encodes and decodes the nonempty OID sequence in
[RFC 5280 section 4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12).
Its `to_der` / `from_der` methods enforce DER and ASN.1 byte, element, depth and
OID-arc limits. Unknown purposes, order and duplicates are preserved; decoded
OID vectors own their data. `contains(oid)` performs exact membership testing.
Helpers provide `extended_key_usage_oid`, `any_extended_key_usage_oid`,
`server_auth_oid`, `client_auth_oid`, `code_signing_oid`, `email_protection_oid`,
`time_stamping_oid` and `ocsp_signing_oid`. Place its DER in `Extension.value_der`
with `extended_key_usage_oid()`. Exact membership does not expand
`anyExtendedKeyUsage` into other OIDs; certificate purpose, criticality and key
usage combination policies remain the caller's responsibility.

`Extension` preserves the OID, critical flag, and the DER value inside its OCTET STRING. A false critical flag is omitted as the ASN.1 default; a decoder rejects an explicitly encoded false. `new_typed` and `decode_value` apply a caller-supplied `asn1::Schema` to the inner value. `encode_extensions` and `decode_extensions` handle the nonempty extension SEQUENCE and reject duplicate OIDs. `AlgorithmIdentifier` keeps optional parameters as explicit DER bytes; it does not infer algorithm-specific parameter rules.

```goml
use ecosystem::asn1;
use ecosystem::x509::pkix;
use ecosystem::x509::pkix::{Attribute, DirectoryValue, Name};

fn subject_der() -> Result[Vec[u8], asn1::Error] {
    let subject = Name {
        rdns: Vec::from_array([Vec::from_array([Attribute {
            oid: pkix::common_name_oid(),
            value: DirectoryValue::Utf8("example.org"),
        }])]),
    };
    subject.to_der(asn1::Limits::standard())
}
```

The default ASN.1 limits are 1 MiB of input/output, 32 levels, 10,000 elements, and 64 OID arcs; callers can lower them. Known primitive types and string forms are validated. For unknown raw values, the library validates DER tag/length structure and nested constructed elements but cannot validate type-specific constraints without a schema. An extension's OCTET STRING must contain exactly one structurally valid DER value. Errors are recoverable `asn1::Error` values. Names are represented as data, not normalized for RFC 4514 comparison or identity matching.

Run `(cd ../verification && just ecosystem-test x509)` from this library repository to verify the library and example, including independent downstream verification.

## Development and examples

Requires GoML 0.1.56 or newer. The `examples/basic/` example shares the root manifest and its dependencies. From the library root, run:

```sh
goml run --example basic
goml test
goml verify --timeout 300s
```

`goml test` builds the example and runs its tests. `goml verify` repeats the example checks as an independent module against an isolated registry snapshot. `(cd ../verification && just ecosystem-test x509)` also retains the library-specific smoke and compatibility checks.
