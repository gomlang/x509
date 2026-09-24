# PKIX data structures

`ecosystem::x509::pkix` implements the DER data structures for distinguished names, object identifiers, extensions, and algorithm identifiers described by [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1). It depends on `ecosystem::asn1` for bounded, canonical tag/length parsing, OID encoding, and explicit typed schemas. It does not parse complete certificates, verify signatures or chains, choose trusted roots, or implement TLS.

`Name` preserves the ordered sequence of RDNs and every multi-valued RDN's SET members. `Name::to_der` sorts each SET by the complete encoded DER element, as DER requires; `Name::from_der` rejects unsorted SETs. A `Name` may be empty because RFC 5280 permits an empty subject with a critical subject alternative name; applications must apply issuer and subject profile rules in their own certificate context. Attributes carry OID arcs and a `DirectoryValue`. UTF8String, PrintableString, IA5String, BMPString, and UniversalString are decoded to validated GoML strings. Legacy TeletexString bytes and unknown tag values are retained explicitly for round trips; they are not silently reinterpreted as UTF-8. Named OID helpers cover common name attributes, basic constraints, key usage, and subject alternative names.

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

Run `(cd ../verification && just ecosystem-test x509)` from this library repository to verify the library and independent versioned consumer.
