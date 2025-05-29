---
v: 3
docname: draft-yusef-tls-dual-certs-latest
title: "Post-Quantum Traditional (PQ/T) Hybrid Authentication with Dual Certificates in TLS 1.3"
abbrev: "Dual Certs in TLS"
cat: std
ipr: trust200902
consensus: 'true'
submissiontype: IETF
lang: en
date:
number:
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
  docmapping: yes
area: "sec"
wg: TLS Working Group
keyword:
 - PKI
 - Post-Quantum Traditional (PQ/T) Hybrid Authentication
 - PQC
 - TLS
#github: "hannestschofenig/tls-dual-certs"
stand_alone: yes
author:
 -    ins: R. Shekh-Yusef
      fullname: Rifaat Shekh-Yusef
      organization: Ciena
      country: Canada
      email: rifaat.s.ietf@gmail.com
 -    ins: H. Tschofenig
      fullname: Hannes Tschofenig
      organization: University of Applied Sciences Bonn-Rhein-Sieg
      abbrev: H-BRS
      country: Germany
      email: hannes.tschofenig@gmx.net
 -    ins: M. Ounsworth
      fullname: Mike Ounsworth
      organization: Entrust
      country: Canada
      email: mike.ounsworth@entrust.com
 -    ins: Y. Sheffer
      fullname: Yaron Sheffer
      organization: Intuit
      country: Israel
      email: yaronf.ietf@gmail.com
 -    ins: T. Reddy
      fullname: Tirumaleswar Reddy
      organization: Nokia
      country: India
      email: kondtir@gmail.com
 -
    ins: "Y. Rosomakho"
    fullname: Yaroslav Rosomakho
    organization: Zscaler
    email: yrosomakho@zscaler.com

normative:
  RFC2119:
  RFC8446:
  I-D.ietf-tls-tlsflags:
  RFC7250:

informative:
  RFC9261:
  TLS-Ext-Registry:
     author:
        org: IANA
     title: Transport Layer Security (TLS) Extensions
     target: https://www.iana.org/assignments/tls-extensiontype-values
     date: May 2025

--- abstract

This document extends the TLS 1.3 authentication mechanism to allow the use of two certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the session.

--- middle

#  Introduction

There are several potential mechanisms to address concerns related to the anticipated emergence of cryptographically relevant quantum computers (CRQCs). While the encryption-related aspects are covered in other documents, this document focuses on the authentication component of the TLS 1.3 handshake {{RFC8446}}.

One approach is the use of dual certificates: issuing two distinct certificates for the same end entity — one using a traditional algorithm (e.g., ECDSA), and the other using a post-quantum (PQ) algorithm (e.g., ML-DSA).

This document defines how TLS 1.3 can utilize such certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the session.

It also addresses the challenges of integrating hybrid authentication in TLS 1.3 while balancing backward compatibility, forward security, and deployment practicality.

This document makes changes to the Certificate and CertificateVerify messages to take advantage of both certificates when authenticating the end entity.

# Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

# Scope

This document is intended for use in closed-network deployments, where a single administrative entity manages both TLS peers. It is not designed for use in open or public network environments where peers are operated independently.

The approach described herein is also compatible with FIPS-compliant deployments, as it supports the continued use of FIPS-approved traditional signature algorithms during the TLS handshake. This enables systems to maintain regulatory compliance while incrementally introducing post-quantum authentication mechanisms using Exported Authenticators.

The proposed mechanism is fully backward compatible: traditional certificates and authentication methods remain functional with existing TLS 1.3 implementations. As cryptographically relevant quantum computers (CRQCs) emerge, deployments can transition by gradually disabling traditional authentication and enabling post-quantum–only authentication. This strategy offers a smooth migration path, ensuring long-term cryptographic agility, regulatory compliance, and operational continuity without disrupting existing infrastructure.

# Flags Extension

Client and servers use the TLS flags extension
{{I-D.ietf-tls-tlsflags}} to indicate support for the functionality
defined in this document.  We call this the "dual_cert"
extension and the corresponding flag is called "Dual_Cert"
flag.

The "Dual_Cert" flag proposed by the client in the
ClientHello (CH) MUST be acknowledged in the EncryptedExtensions
(EE), if the server also supports the functionality defined in this
document and is configured to use it.

If the "Dual_Cert" flag is not set, servers ignore any of
the functionality specified in this document and applications that
require perfect forward security will have to initiate a full
handshake.

The "Dual_Cert" flag is assigned the value (TBD1).

If both client and server support the "dual_cert" extension,
the Certificate message includes both the traditional and
PQ certificates. The certificates are included as separate entries
and the CertificateVerify message uses several signatures - one for
each end-entity certificate.

# Certificate Extension

To convey a new certificate payload a new certificate type
"Dual Certificate" is registered via RFC 7250.

The structure of the message is shown below:

~~~
  enum {
      X509(0),
      RawPublicKey(2),
      DualCert(TBD2),
      (255)
  } CertificateType;

  struct {
       /* Traditional cryptographic certs */
       opaque cert_data<1..2^24-1>;
       /* PQC certs */
       opaque cert_data<1..2^24-1>;
  } DualCert;

  struct {
      select (certificate_type) {
          case RawPublicKey:
            /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
            opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

          case X509:
            opaque cert_data<1..2^24-1>;

          case DualCert:
            DualCert dual_cert_data<1..2^24-1>;
      };
      Extension extensions<0..2^16-1>;
  } CertificateEntry;

  struct {
      opaque certificate_request_context<0..2^8-1>;
      CertificateEntry certificate_list<0..2^24-1>;
  } Certificate;
~~~

This document allows for more than one CertificateEntry in the Certificate structure.

# CertificateVerify Extension

The structure of the CertificateVerify message is:

~~~
  struct {
      SignatureScheme algorithm;
      opaque signature<0..2^16-1>;
      SignatureScheme pq_algorithm;
      opaque pq_signature<0..2^16-1>;
  } CertificateVerify;
~~~

As with the Certificate message, this message allows more than one signature, one per CertificateEntry.

#  IANA Considerations

IANA is requested to add the following entry to the "TLS Flags"
extension registry {{TLS-Ext-Registry}}:

 *  Value: TBD1
 *  Flag Name: dual_cert
 *  Messages: CH, EE
 *  Recommended: Y
 *  Reference: [[This document]]

This document adds a new entry to the "TLS Certificate Types"
registry defined in {{RFC7250}}:

-  Value: TBD2
-  Description: Dual Certificate
-  Reference: [[This document]]

#  Security Considerations

tbd

# Acknowledgments

We would like to thank ... for their comments.

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

As an alternative to the current design, the use of a Composite Signature is possible. This approach requires registering new cryptographic algorithm - one for each desireable combination. The benefit of this approach is the ease of integration into an existing implementation since the structure of the message remains unchanged.

~~~
struct {
   SignatureScheme algorithm;
   opaque signature<0..2^16-1>;
} CertificateVerify;
~~~

