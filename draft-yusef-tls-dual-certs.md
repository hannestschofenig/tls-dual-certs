---
title: "Post-Quantum Traditional (PQ/T) Hybrid Authentication with Dual Certificates in TLS 1.3"
abbrev: "Dual Certs in TLS"
category: std

docname: draft-yusef-tls-dual-certs-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - PKI
 - Post-Quantum Traditional (PQ/T) Hybrid Authentication
 - PQC
 - TLS
venue:
  group: TLS
#  type: Working Group
  mail: tls@ietf.org
  arch: https://datatracker.ietf.org/wg/tls/about/
#  github: "lamps-wg/csr-attestation"
#  latest: "https://lamps-wg.github.io/csr-attestation/draft-ietf-lamps-csr-attestation.html"

author:
  -
    ins: R. Shekh-Yusef
    name: Rifaat Shekh-Yusef
    org: Ciena
    country: Canada
    email: rifaat.s.ietf@gmail.com
  -
    ins: H. Tschofenig
    name: Hannes Tschofenig
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    country: Germany
    email: Hannes.Tschofenig@gmx.net

normative:
  RFC8446:
  I-D.ietf-tls-tlsflags:

informative:
  RFC9261:

--- abstract

tbd

--- middle

# Introduction

There are several potential mechanisms to address concerns related to the anticipated emergence of cryptographically relevant quantum computers (CRQCs). While the encryption-related aspects are covered in other documents, this document focuses on the authentication component of the TLS 1.3 handshake {{RFC9261}}.

One approach is the use of dual certificates: issuing two distinct certificates for the same end entity — one using a traditional algorithm (e.g., ECDSA), and the other using a post-quantum (PQ) algorithm (e.g., ML-DSA).

This document defines how TLS 1.3 can utilize such certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the session.

It also addresses the challenges of integrating hybrid authentication in TLS 1.3 while balancing backward compatibility, forward security, and deployment practicality.

This document makes changes to the Certificate and CertificateVerify messages to take advantage of both certificates when authenticating the end entity.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Flags Extension

This specification uses the tls_flags extension defined in
{{I-D.ietf-tls-tlsflags}} to allow a client and a server to negotiate
support for this extension.

The dual_cert_support flag is assigned the value (TBD1) and is used in the ClientHello (CH) and the ServerHello (SH).

If the client supports the dual_cert_support extension it can express support for it in the flags extension of the ClientHello message.

If the server supports the extension, it includes the dual_cert_support extension in the ServerHello message. If the server does not support this extension or prefers not to use it, it proceeds without setting the flag.

If both client and server support dual certificates, the Certificate message includes both the traditional and PQ certificates. The certificates can be included as separate entries or as a composite certificate. The CertificateVerify message use parallel signatures (one for each certificate).

# Certificate Extension

Structure of this message:

~~~
  enum {
	  X509(0),
	  RawPublicKey(2),
	  (255)
  } CertificateType;

  struct {
	  select (certificate_type) {
		  case RawPublicKey:
			/* From RFC 7250 ASN.1_subjectPublicKeyInfo */
			opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

		  case X509:
			opaque cert_data<1..2^24-1>;
	  };
	  Extension extensions<0..2^16-1>;
  } CertificateEntry;

  struct {
	  opaque certificate_request_context<0..2^8-1>;
	  CertificateEntry certificate_list<0..2^24-1>;
	  opaque pq_certificate_request_context<0..2^8-1>;
	  CertificateEntry pq_certificate_list<0..2^24-1>;
  } Certificate;
~~~

This document allows for more than one CertificateEntry in the Certificate structure.

NOTE: Discuss the size impact of including two certificates, instead of one. Maybe in such cases, the end entity should only include the leaf certificate, and not include the issuer and root CA certificates.

# IANA Considerations

tbd

# Security Considerations

tbd

--- back


# Design Alternatives

There are several approaches for conveying two certificate chains and demonstrating possession of the corresponding private keys.

The approaches outlined below assume two distinct certificate-based authentication exchanges during the TLS handshake. An alternative mechanism is the use of Exported Authenticators, as defined in RFC 9261, which enables the use of one certificate during the initial handshake and a second certificate after the handshake has completed.

RFC 9261 {{RFC9261}} relies on the application-layer protocol to carry the Certificate, CertificateVerify, and Finished messages outside the initial handshake. Unlike the post-handshake authentication mechanism defined in TLS 1.3, RFC 9261 supports mutual authentication, allowing both client and server to authenticate after the handshake.

## Certificate Design

### Certificate Message Extension

Utilize the existing Certificate message extensions to carry additional certificates. Define a new pq_certificate extension to carry the post-quantum certificate.

This extension can be included in the extensions field of the CertificateEntry structure:

~~~
struct {
	ExtensionType extension_type; 
	opaque pq_certificate<1..2^24-1>;
} PQCertificateExtension;
~~~

### Separate Certificate Entries

Use the existing Certificate structure to include both traditional and PQ certificates as separate entries within the certificate_list:

Each CertificateEntry can carry either a traditional certificate or a PQ certificate. The extensions field within CertificateEntry can be used to indicate the type of certificate (e.g., traditional or PQ).

## CertificateVerify Message Design

As an alternative to the current design, the use of a Composite Signature is possible. This approach requires registering new cryptographic algorithm - one for each desireable combination.
The benefit of this approach is the ease of integration into an existing implementation since the structure of the message remains unchanged.

~~~
struct {
	SignatureScheme algorithm;
	opaque signature<0..2^16-1>;
} CertificateVerify;
~~~

# Acknowledgments

We would like to thank xyz.
