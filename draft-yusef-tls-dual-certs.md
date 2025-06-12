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
 -    ins: "Y. Rosomakho"
      fullname: Yaroslav Rosomakho
      organization: Zscaler
      email: yrosomakho@zscaler.com
updates: RFC9261, RFC8446

--- abstract

This document extends the TLS 1.3 authentication mechanism to allow the use of two certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the session.

--- middle

#  Introduction

There are several potential mechanisms to address concerns related to the anticipated emergence of cryptographically relevant quantum computers (CRQCs). While the encryption-related aspects are covered in other documents, this document focuses on the authentication component of the {{!TLS=RFC8446}} handshake.

One approach is the use of dual certificates: issuing two distinct certificates for the same end entity — one using a traditional algorithm (e.g., ECDSA), and the other using a post-quantum (PQ) algorithm (e.g., ML-DSA).

This document defines how TLS 1.3 can utilize such certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the session.

It also addresses the challenges of integrating hybrid authentication in TLS 1.3 while balancing backward compatibility, forward security, and deployment practicality.

This document makes changes to the Certificate and CertificateVerify messages to take advantage of both certificates when authenticating the end entity.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Scope

This document is intended for use in closed-network deployments, where a single administrative entity manages both TLS peers. It is not designed for use in open or public network environments where peers are operated independently.

The approach described herein is also compatible with FIPS-compliant deployments, as it supports the continued use of FIPS-approved traditional signature algorithms during the TLS handshake. This enables systems to maintain regulatory compliance while incrementally introducing post-quantum authentication mechanisms using Exported Authenticators.

The proposed mechanism is fully backward compatible: traditional certificates and authentication methods remain functional with existing TLS 1.3 implementations. As cryptographically relevant quantum computers (CRQCs) emerge, deployments can transition by gradually disabling traditional authentication and enabling post-quantum–only authentication. This strategy offers a smooth migration path, ensuring long-term cryptographic agility, regulatory compliance, and operational continuity without disrupting existing infrastructure.


# Design Overview

This document introduces a mechanism to enable dual-certificate authentication in TLS 1.3. The primary objective is to allow each TLS peer to present two certificate chains—typically a traditional cryptographic chain and a post-quantum (PQ) chain—thereby requiring an attacker to break both authentication algorithms to impersonate a peer.

The design builds on existing TLS 1.3 structures and introduces minimal protocol changes. It is applicable to both client and server authentication and is compatible with the Exported Authenticators mechanism.

## Signature Algorithm Negotiation

A new extension, `secondary_signature_algorithms`, is defined to negotiate support for a second category of signature algorithms, typically post-quantum schemes. This extension is structurally identical to signature_algorithms and is used in the same handshake messages:

- In the `ClientHello`, it indicates the client's supported secondary (PQ) signature algorithms for server authentication.
- In the `CertificateRequest`, it indicates the server's supported secondary (PQ) signature algorithms for client authentication.

This allows both endpoints to signal independently two distinct algorithms for dual authentication.

The `secondary_signature_algorithms` can also be used in `extensions` of `CertificateRequest` and `ClientCertificateRequest` structures of Authenticator Request message of Exported Authenticators as defined in {{Section 4 of !EXPORTED-AUTH=RFC9261}}.

## Certificate Chain Encoding

TLS 1.3 defines the `Certificate` message to carry a list of certificate entries representing a single chain. This document reuses the same structure to convey two certificate chains by concatenating them and inserting a delimiter in the form of a zero-length certificate entry.

A zero-length certificate is defined as a `CertificateEntry` with an empty `cert_data` field and omitted `extensions` field. TLS 1.3 prohibits the use of empty certificate entries, making this delimiter unambiguous. Implementations MUST treat all entries before the zero-length delimiter as the first certificate chain (typically classic), and all entries after it as the second certificate chain (typically post-quantum).

This encoding applies equally to the `CompressedCertificate` message and to the `Certificate` message of Exported Authenticators as defined in {{Section 5.2.1 of EXPORTED-AUTH}}.

## CertificateVerify Signatures

The `CertificateVerify` message is extended to include two digital signatures:

1. One computed using a signature algorithm negotiated via signature_algorithms.
1. One computed using an algorithm negotiated via secondary_signature_algorithms.

Each signature is computed over the transcript hash as specified in TLS 1.3, but with distinct context strings to domain-separate the two operations. This approach prevents attackers from comparing timing characteristics or reusing one signature in place of the other.

This encoding applies equally to the `CertificateVerify` message of Exported Authenticators as defined in {{Section 5.2.2 of EXPORTED-AUTH}}.

The order of the signatures in the message MUST correspond to the order of the certificate chains in the Certificate message.

## Enforcement Policy

A new TLS flag, `dual_certificate_required`, is defined using the {{!TLS-FLAGS=I-D.ietf-tls-tlsflags}} extension. This flag may be set in either direction:

- When set by the client in `ClientHello`, it indicates that the server MUST provide both certificate chains and both signatures.
- When set by the server in `CertificateRequest`, it indicates that the client MUST do the same.

If the flag is not set, the peer MAY choose to send either one or two certificate chains, depending on local policy and capabilities. This flexibility supports incremental deployment of dual-certificate authentication.

# Protocol Changes

This section defines the normative changes to TLS 1.3 required to support dual-certificate authentication. These changes extend existing handshake messages and introduce one new extension and one new TLS flag.

## `secondary_signature_algorithms` Extension

A new extension, `secondary_signature_algorithms`, is defined to allow peers to advertise support for a secondary category of signature algorithms, typically post-quantum schemes.

### Structure

The structure of the extension is identical to that of `signature_algorithms` defined in {{Section 4.2.3 of TLS}}

~~~~~~~~~~ ascii-art
struct {
    SignatureScheme supported_signature_algorithms<2..2^16-2>;
} SignatureSchemeList;
~~~~~~~~~~
{: title="Contents of secondary_signature_algorithms extension"}

Each `SignatureScheme` is a 2-octet value identifying a supported signature algorithm as defined in TLS SignatureScheme IANA registry.

### Use in Handshake and Exported Authenticator Messages

The client MAY include this extension in `ClientHello` message to indicate which secondary algorithms it supports for verifying the server's signature. The server MAY include this extension in `CertificateRequest` message to indicate which secondary algorithms it supports for verifying the client's signature. This extension MAY be included in an Authenticator Request by the requestor to signal support for secondary signature algorithms in the response.

This extension MUST NOT be used unless the `signature_algorithms` extension is also present in the same message.

If the extension is present in `ClientHello`, `CertificateRequest` or Authenticator Request, the peer MAY respond with a dual-certificate authentication structure. If the extension is absent, the peer MUST NOT send a second certificate chain or a second signature.

The presence of this extension alone does not mandate dual authentication; enforcement is controlled by the `dual_certificate_required` TLS flag.

## `dual_certificate_required` TLS Flag

The dual_certificate_required flag is conveyed using the {{TLS-FLAGS}} extension.

### Semantics

When set in `ClientHello`, it indicates that the client requires the server to present both certificate chains and both signatures. When set in `CertificateRequest`, it indicates that the server requires the client to present both certificate chains and both signatures if the client is authenticating itself during TLS handshake.

If the flag is set and the peer provides only one chain or one signature, the handshake MUST be aborted with an `dual_certificate_required` alert.

This flag MAY be included in TLS flags extension of Authenticator Request message of Exported Authenticators.

If the flag is not set, the peer MAY provide either one or two certificate chains, depending on local policy and negotiated capabilities.

## Certificate Message Encoding {#certificate}

TLS 1.3 defines the `Certificate` message as follows:

~~~~~~~~~~ ascii-art
struct {
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;
} Certificate;
~~~~~~~~~~
{: title="TLS 1.3 Certificate message"}

This document extends the semantics of `certificate_list` to support two logically distinct certificate chains, encoded sequentially and separated by a delimiter.

### Delimiter

The delimiter is a zero-length certificate entry, defined as:

~~~~~~~~~~ ascii-art
struct {
    opaque cert_data<0..0>;
} CertificateEntry;
~~~~~~~~~~
{: title="Delimiter between Certificate chains"}

TLS 1.3 prohibits empty certificate entries, so this delimiter is unambiguous.

All entries before the delimiter are treated as the first certificate chain, all entries after the delimiter are treated as the second certificate chain.

A peer receiving this structure MUST validate each chain independently according to its corresponding signature algorithm. The end-entity certificate MUST be the first entry in both the first and second certificate chains. The first certificate chain MUST contain certificates whose public key is compatible with one of the algorithms listed in the `signature_algorithms` or `signature_algorithms_cert` extension, if present. The second certificate chain MUST contain certificates whose public key is compatible with one of the algorithms listed in the `secondary_signature_algorithms` extension.

This encoding applies equally to the `CompressedCertificate` message and to `Certificate` message of Exported Authenticators.

## CertificateVerify Message {#certificate-verify}

The `CertificateVerify` message is extended to carry two independent signatures. Its modified structure is as follows:

~~~~~~~~~~ ascii-art
struct {
    SignatureScheme first_algorithm;
    opaque classic_signature<0..2^16-1>;
    SignatureScheme second_algorithm;
    opaque pq_signature<0..2^16-1>;
} CertificateVerify;
~~~~~~~~~~
{: title="CertificateVerify message"}

Each signature covers the transcript hash as in TLS 1.3, but with a distinct context string for domain separation.

### Context Strings

First signature context string is matching TLS 1.3 specification:

- for a server context string is "TLS 1.3, server CertificateVerify"
- for a client context string is "TLS 1.3, client CertificateVerify"

Second signature context string is defined as follows:

- for a server, secondary context string is "TLS 1.3, server secondary CertificateVerify"
- for a client, secondary context string is "TLS 1.3, client secondary CertificateVerify"

Implementations MUST verify both signatures and MUST associate each with its corresponding certificate chain.

This dual-signature structure applies equally to `CertificateVerify` messages carried in Exported Authenticators with second signature using "Secondary Exported Authenticator" as the context string.

# Client-Driven Authentication Requirements

This section defines expected client and server behavior under various client configurations. Each case reflects a different client capability and authentication policy, based on how the client populates the `signature_algorithms`, `signature_algorithms_cert`, and `secondary_signature_algorithms` extensions, and whether it sets the `dual_certificate_required` flag.

## Type 1: Classic-Only Clients

Client supports only traditional signature algorithms (e.g., RSA, ECDSA).

Client behavior:

- Includes supported classical algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Does not include `secondary_signature_algorithms`.
- Does not set `dual_certificate_required` flag.

To satisfy this client, the server MUST send a single certificate chain with compatible classical algorithms and include a single signature in CertificateVerify.

## Type 2: Dual-Compatible, PQ Optional (Classic Primary)

Client supports both classical and PQ authentication. It allows the server to send either a classical chain alone or both chains.

Client behavior:

- Includes supported classical algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Includes supported PQ algorithms in `secondary_signature_algorithms`.
- Does not set `dual_certificate_required` flag.

To satisfy this client, the server MUST either:

- Provide a single certificate chain with compatible classical algorithms and include a single signature in CertificateVerify
- Provide a classical certificate chain followed by a PQ certificate chain as described in {{certificate}} and two signatures in CertificateVerify as described in {{certificate-verify}}

## Type 3: Strict Dual

Client requires both classical and PQ authentication to be performed simultaneously.

Client behavior:

- Includes supported classical algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Includes supported PQ algorithms in `secondary_signature_algorithms`.
- Sets `dual_certificate_required` flag.

To satisfy this client, the server MUST provide a classical certificate chain followed by a PQ certificate chain as described in {{certificate}} and two signatures in CertificateVerify as described in {{certificate-verify}}

## Type 4: Dual-Compatible, Classic Optional (PQ Primary)

Client supports both classical and PQ authentication. It allows the server to send either a PQ chain alone or both chains.

Client behavior:

- Includes supported PQ algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Includes supported classical algorithms in `secondary_signature_algorithms`.
- Does not set `dual_certificate_required` flag.

To satisfy this client, the server MUST either:

- Provide a single certificate chain with compatible PQ algorithms and include a single signature in CertificateVerify
- Provide a PQ certificate chain followed by a classical certificate chain as described in {{certificate}} and two signatures in CertificateVerify as described in {{certificate-verify}}

## Type 5: PQ-Only Clients

Client supports only PQ signature algorithms (e.g., ML-DSA).

Client behavior:

- Includes supported PQ algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Does not include `secondary_signature_algorithms`.
- Does not set `dual_certificate_required` flag.

To satisfy this client, the server MUST send a single certificate chain with compatible PQ algorithms and include a single signature in CertificateVerify.

## Type 6: Flexible

Client supports either classical or PQ authentication and accepts any supported certificate type without requiring both simultaneously.

Client behavior:

- Includes supported classical and PQ algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Does not include `secondary_signature_algorithms`.
- Does not set `dual_certificate_required` flag.

To satisfy this client, the server MUST send a single certificate chain with compatible classical or PQ algorithms and include a single signature in CertificateVerify.

#  Security Considerations

## Signature Association and Parsing Robustness

Implementations MUST strictly associate each `CertificateVerify` signature with the corresponding certificate chain, based on their order relative to the zero-length delimiter in the `Certificate` message. Failure to properly align signatures with their intended certificate chains may result in incorrect validation or misattribution of authentication.

Certificate parsing logic MUST reject messages that contain more than one zero-length delimiter, or that place the delimiter as the first or last entry in the certificate list.

## Signature Validation Requirements

Both signatures in the `CertificateVerify` message MUST be validated successfully and correspond to their respective certificate chains. Implementations MUST treat failure to validate either signature as a failure of the authentication process. Silent fallback to single-certificate verification undermines the dual-authentication model and introduces downgrade risks.

## Side-Channel Resistance

Since both `CertificateVerify` operations involve signing the transcript using different cryptographic primitives, care MUST be taken to avoid leaking timing or other side-channel information. Implementers MUST ensure constant-time execution and avoid conditional branching that could reveal whether one or both signatures are present or valid.

Distinct context strings are REQUIRED for the two signatures to prevent cross-protocol misuse or collision attacks.

## Dual Certificate Policy Enforcement

When the `dual_certificate_required` flag is set by a peer, failure to provide two certificate chains and two corresponding signatures MUST result in handshake failure. This enforcement MUST NOT be bypassed by falling back to a single-certificate configuration. Implementations MUST emit a `dual_certificate_required` alert when this requirement is violated.

## Cryptographic Independence

To achieve the intended security guarantees, implementers and deployment operators MUST ensure that the two certificate chains rely on cryptographically independent primitives.

## Certificate Usage and Trust

Certificate chains must be validated independently, including trust anchors, certificate usage constraints, expiration, and revocation status. Operators should consider whether the two chains are validated against the same or distinct trust roots, and what implications this has for overall trust decisions.

#  IANA Considerations

This specification registers the `secondary_signature_algorithms` TLS extension, `dual_certificate_required` TLS Flag and `dual_certificate_required` TLS alert.

## TLS extension

IANA is requested to assign a new value from the TLS ExtensionType Values registry:

 *  Extension Name: secondary_signature_algorithms
 *  TLS 1.3: CH, CR
 *  DTLS-Only: N
 *  Recommended: Y
 *  Reference: [[This document]]

## TLS flag

IANA is requested to add the following entry to the "TLS Flags" extension registry:

 *  Value: TBD
 *  Flag Name: dual_certificate_required
 *  Messages: CH, CR
 *  Recommended: Y
 *  Reference: [[This document]]

## TLS alert

IANA is requested to add the following entry to the "TLS Alerts" registry:

 *  Value: TBD
 *  Description: dual_certificate_required
 *  DTLS-OK: Y
 *  Reference: [[This document]]
 *  Comment: None

# Acknowledgments

We would like to thank ... for their comments.

--- back

# Informal Requirements for Dual TLS Certificate Support

## General TLS Semantics

### Protocol Flow Consistency

Dual certificate authentication must follow the same logical flow as standard TLS certificate authentication, including integration with `Certificate`, `CertificateVerify`, and `Finished` messages.

### Minimal Protocol Changes

Any additions or modifications to the TLS protocol must be minimal to ease deployment, reduce implementation complexity and minimize new security risks.

### mTLS support

The mechanism must support both server and client authentication scenarios. In case of mutual authentication dual certificates may be used unidirectionally as well as bidirectionally.

### Exported Authenticators Compatibility

The mechanism must be usable with Exported Authenticators (RFC 9261) for mutual authentication in post-handshake settings.

## Certificate Handling Semantics

### Independent Chain Usability

Each certificate chain (e.g., classic and PQ) must be independently usable for authentication, allowing endpoints to fall back to classic or PQ-only validation if necessary.

### Unambiguous Chain Separation

The mechanism must clearly distinguish and delimit multiple certificate chains to prevent ambiguity or misinterpretation.

### Chain-Specific Signature Algorithms

Each certificate chain must be associated with its own set of supported signature algorithms, allowing negotiation of appropriate algorithms for classic and PQ use cases.

### Multiple Chains Support (Generalisation)

The mechanism must be designed in a way that could support more than two certificate chains in the future, not just hardcoded to classic + PQ.

## Use Case and Deployment Flexibility

### Backward Compatibility

When only one certificate chain is used, the mechanism must remain compatible with existing TLS 1.3 endpoints unaware of dual-certificate support or willing to use only a single certificate.

### Policy Signalling

A mechanism must exist for one party (client or server) to signal whether dual certificate presentation is required, optional, or not supported, to coordinate authentication expectations.

### Support for Non-PQC Multi-Cert Use Cases

The mechanism must be expandable to other multi-certificate use cases such as attested TLS

### Mitigation of Side Channels

The mechanism should avoid constructions that enable side-channel attacks by observing how distinct algorithms are applied to the same message.

### Transparency in Signature Validation

The order and pairing between certificates and their corresponding signatures must be explicit, so verifiers can unambiguously match them.
