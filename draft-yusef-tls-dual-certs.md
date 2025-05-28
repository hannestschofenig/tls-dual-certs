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
 -    ins: T. Reddy
      fullname: Tirumaleswar Reddy
      organization: Nokia
      country: India
      email: kondtir@gmail.com
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

normative:
  RFC2119:
  RFC8446:

informative:
  RFC9261:


--- abstract

This document extends the TLS 1.3 authentication mechanism to allow the use of two certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the TLS session.

It defines a mechanism using Exported Authenticators defined in RFC9261 to enable authentication with a traditional certificate during the TLS handshake and PQC certificate after the TLS handshake.

--- middle

#  Introduction

There are several potential mechanisms to address concerns related to the anticipated emergence of cryptographically relevant quantum computers (CRQCs). While the encryption-related aspects are covered in other documents, this document focuses on the authentication component of the TLS 1.3 handshake.

One approach is the use of dual certificates: issuing two distinct certificates for the same end entity, one using a traditional algorithm (e.g., ECDSA), and the other using a post-quantum (PQ) algorithm (e.g., ML-DSA).

This document defines how TLS 1.3 {{RFC8446}} can utilize such certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the TLS session.

It also addresses the challenges of integrating hybrid authentication in TLS 1.3 while balancing backward compatibility, forward security, and deployment practicality.

This document leverages Exported Authenticators {{RFC9261}} to authenticate with a traditional certificate during the TLS handshake and a PQC certificate after the TLS handshake.

# Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

# Scope

This document is intended for use in closed-network deployments where a single entity manages both the TLS peers. It is not designed for deployments where TLS peers operate in public networks.

This approach is also compatible with deployments that require compliance with FIPS certification, as it allows the use of existing FIPS-approved traditional signature algorithms during the TLS handshake. This ensures that systems can remain compliant with FIPS while still incorporating post-quantum authentication using Exported Authenticators.

The mechanism is fully backward compatible, as traditional certificates and authentication continue to work with existing TLS 1.3 implementations. As CRQCs emerge, deployments can progressively transition by disabling traditional authentication and enabling pure PQ-based authentication. This flexibility ensures that long-term security, compliance and backward compatibiltiy can be maintained without disruption to existing infrastructure.

# Design of Dual Certificate Authentication

There are several approaches for conveying two certificate chains and demonstrating possession of the corresponding private keys.

The approach outlined in the document assumes two distinct certificate-based authentication exchanges during the TLS handshake and post-handsake. {{RFC9261}} relies on the application-layer protocol to carry the Certificate, CertificateVerify, and Finished messages outside the initial handshake. Unlike the post-handshake authentication mechanism defined in TLS 1.3, {{RFC9261}} supports mutual authentication, allowing both client and server to authenticate after the handshake.

# Post-Handshake PQ Certificate Using Exported Authenticators

In scenarios where TLS endpoints wish to authenticate using a traditional certificate during the TLS handshake (for compliance or performance reasons) and use a PQ certificate for long-term cryptographic assurance, {{RFC9261}} provides a suitable framework.

In such deployments, either endpoint (client or server) can perform traditional certificate-based authentication during the TLS handshake. Following the handshake, an Authenticator Request can be initiated by either party, and the responding peer provides a post-quantum certificate using an Exported Authenticator. This authenticator includes the PQ certificate, a corresponding CertificateVerify, and a Finished message.

This bidirectional authentication approach ensures that post-quantum identities are strongly bound to the underlying TLS connection while maintaining backward compatibility with existing TLS implementations and minimizing initial handshake overhead.

The use of dual-certificate authentication via Exported Authenticators is useful where post-quantum algorithms introduce significant performance or message size impacts that are best avoided during the TLS handshake.

#  IANA Considerations

This document has no IANA actions.

#  Security Considerations

## Downgrade and Zero-Day Attack Protection

The mechanism proposed in this document is designed to mitigate a range of cryptographic transition risks.

## Dual Authentication Binding

By using a traditional certificate during the TLS handshake and a PQ certificate after the handshake via Exported Authenticators {{RFC9261}}, the solution ensures that authentication relies on two distinct algorithms. The security of the session is hardened because an attacker must break both the traditional and the post-quantum algorithms to successfully impersonate a peer.

This dual-layered authentication can help defend against downgrade attacks, in which a CRQC-enabled adversary compromises one of the algorithms (e.g., a traditional certificate) and attempts to suppress the stronger authentication stage. However, protection against such attacks depends entirely on the deployment's connection policy which must enforce that PQ authentication using Exported Authenticators is required and that connections lacking it are rejected. In such environments, the TLS session's trustworthiness ultimately depends on the stronger of the two algorithms.

## Resilience to Zero-Day CRQC Attacks

The proposed mechanism also anticipates a zero-day scenario, where CRQCs become available and are exploited covertly much like the sudden exploitation of a software vulnerability. In such cases, victims may unknowingly rely on compromised traditional algorithms for authentication.

The use of PQ authentication after the handshake ensures that:

- Even if the handshake (traditional) certificate is silently broken by a CRQC,
- The attacker will still have to break the post-handshake PQ authentication bound to the session.

This layered approach buys time for the ecosystem to detect, respond, and transition securely, even under zero-day attacks.

## Resilience to PQ Algorithm Implementation Failures

This mechanism also accounts for the possibility of implementation vulnerabilities or future cryptanalytic breakthroughs affecting post-quantum algorithms (e.g., ML-DSA). If a flaw enables certificate forgery, the traditional authentication step offers a fallback layer of assurance.

## Migration to PQ-Only Authentication

The proposed approach is fully backward compatible with existing TLS 1.3 implementations and can be deployed incrementally in closed-network environments. It enables gradual adoption of post-quantum (PQ) authentication without requiring changes to the TLS handshake itself.

As the cryptographic landscape evolves, deployments can adapt by updating the TLS configuration. With the anticipated availability of CRQCs in the near future, deployments will be able to disable the use of traditional certificates during the handshake and rely solely on PQ certificates.

This flexibility supports a graceful migration path, beginning with hybrid (traditional + PQ) authentication for cryptographic resilience and backward compatibility, and evolving toward pure PQ authentication as cryptographic confidence and ecosystem readiness mature.

Further, this model can avoid the need for dual truststore transitions when used in conjunction with composite certificates. Composite certificates allow a single certificate structure to support both traditional and PQ algorithms. 

# Acknowledgments

We would like to thank ... for their comments.

--- back

