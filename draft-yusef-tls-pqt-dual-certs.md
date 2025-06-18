---
v: 3
docname: draft-yusef-tls-pqt-dual-certs-latest
title: "Post-Quantum Traditional (PQ/T) Hybrid Authentication with Dual Certificates in TLS 1.3"
abbrev: "PQ/T Dual Certs in TLS"
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

This document extends the TLS 1.3 authentication mechanism to allow the negotiation and use of two signature algorithms to enable dual-algorithm hybrid authentication, ensuring that an attacker would need to break both algorithms to compromise the session. The two signature algorithms come from two independent certificates that together produce a single `Certificate` and `CertificateVerify` message.

--- middle

#  Introduction

There are several potential mechanisms to address concerns related to the anticipated emergence of cryptographically relevant quantum computers (CRQCs). While the encryption-related aspects are covered in other documents, this document focuses on the authentication component of the {{!TLS=I-D.ietf-tls-rfc8446bis}} handshake.

One approach is the use of dual certificates: issuing two distinct certificates for the same end entity — one using a traditional algorithm (e.g., {{?ECDSA=DOI.10.6028/NIST.FIPS.186-5}}), and the other using a post-quantum (PQ) algorithm (e.g., {{?ML-DSA=I-D.ietf-tls-mldsa}}).

This document defines how TLS 1.3 can utilize such certificates to enable dual-algorithm authentication, ensuring that an attacker would need to break both algorithms to compromise the session.

It also addresses the challenges of integrating hybrid authentication in TLS 1.3 while balancing backward compatibility, forward security, and deployment practicality.

This document defines a new extension `dual_signature_algorithms` to negotiate support for two categories of signature algorithms, typically one set of classic schemes and one set of PQ schemes. It also makes changes to the `Certificate` and `CertificateVerify` messages to take advantage of both certificates when authenticating the end entity.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Scope

The approach described herein is also compatible with FIPS-compliant deployments, as it supports the continued use of FIPS-approved traditional signature algorithms during the TLS handshake.

The proposed mechanism is fully backward compatible: traditional certificates and authentication methods remain functional with existing TLS 1.3 implementations. As cryptographically relevant quantum computers (CRQCs) emerge, deployments can transition by gradually disabling traditional authentication and enabling post-quantum–only authentication. This strategy offers a smooth migration path, ensuring long-term cryptographic agility, regulatory compliance, and operational continuity without disrupting existing infrastructure.


# Design Overview

This document introduces a mechanism to enable dual-certificate authentication in TLS 1.3. The primary objective is to allow each TLS peer to present two certificate chains requiring an attacker to break both authentication algorithms to impersonate a peer. Typically one of the certificate chains is using a traditional cryptographic algorithms while the second leverages post-quantum (PQ) cryptography.

The design builds on existing TLS 1.3 structures and introduces minimal protocol changes. It is applicable to both client and server authentication and is compatible with the Exported Authenticators mechanism {{!EXPORTED-AUTH=RFC9261}}.

A full set of informal design requirements for this specification can be found in {{sec-design-requirements}}.

## Signature Algorithms Negotiation

A new extension, `dual_signature_algorithms`, is defined to negotiate support for two distinct categories of signature algorithms. The extension carries two disjoint lists: one for classical signature algorithms and one for post-quantum signature algorithms.

- In the `ClientHello`, this extension indicates the client's supported classical and PQ signature algorithms for dual certificate server authentication.
- In the `CertificateRequest`, this extension indicates the server's supported classical and PQ signature algorithms for dual certificate client authentication.

This allows both endpoints to signal independently two distinct algorithms for dual authentication.

The `dual_signature_algorithms` can also be used in `extensions` of `CertificateRequest` and `ClientCertificateRequest` structures of Authenticator Request message of Exported Authenticators as defined in {{Section 4 of EXPORTED-AUTH}}.

The `dual_signature_algorithms` extension does not replace `signature_algorithms`. TLS peers MUST include the `signature_algorithms` extension regardless of whether `dual_signature_algorithms` is used. The `signature_algorithms` extension indicates algorithms acceptable for single-certificate authentication and MUST contain either a non-empty list of such algorithms or be empty if only dual-certificate authentication is acceptable.

## Certificate Chain Encoding

TLS 1.3 defines the `Certificate` message to carry a list of certificate entries representing a single chain. This document reuses the same structure to convey two certificate chains by concatenating them and inserting a delimiter in the form of a zero-length certificate entry.

A zero-length certificate is defined as a `CertificateEntry` with an empty `cert_data` field and omitted `extensions` field. TLS 1.3 prohibits the use of empty certificate entries, making this delimiter unambiguous. Implementations MUST treat all entries before the zero-length delimiter as the first certificate chain (typically classic), and all entries after it as the second certificate chain (typically post-quantum).

This encoding applies equally to the `CompressedCertificate` message defined in {{?COMPRESS-CERT=RFC8879}} and to the `Certificate` message of Exported Authenticators as defined in {{Section 5.2.1 of EXPORTED-AUTH}}.

Since TLS 1.3 supports only a single certificate type in each direction, both certificate chains MUST either contain X.509 certificates or certificates of type specified in:

- `server_certificate_type` extension in a `EncryptedExtensions` message for Server certificates
- `client_certificate_type` extension in a `EncryptedExtensions` message for Client certificates

Note that according to {{Section 5.2.1 of EXPORTED-AUTH}} Exported Authenticators support only X.509 certificates.

## CertificateVerify Signatures

The `CertificateVerify` message is extended to include two digital signatures:

1. One computed using a signature algorithm selected from the first list of the `dual_signature_algorithms` extension.
1. One computed using a signature algorithm selected from the second list of the `dual_signature_algorithms` extension.

Each signature is computed over the transcript hash as specified in TLS 1.3, but with distinct context strings to domain-separate the two operations.

This encoding applies equally to the `CertificateVerify` message of Exported Authenticators as defined in {{Section 5.2.2 of EXPORTED-AUTH}}.

The order of the signatures in the message MUST correspond to the order of the certificate chains in the Certificate message: the first signature MUST correspond to a classical algorithm from `first_signature_algorithms` list of `dual_signature_algorithms` extension, while the second signature MUST correspond to a PQ algorithm from `second_signature_algorithms` list of `dual_signature_algorithms` extension.

# Protocol Changes

This section defines the normative changes to TLS 1.3 required to support dual-certificate authentication. These changes extend existing handshake messages and introduce the new extension.

## `dual_signature_algorithms` Extension

A new extension, `dual_signature_algorithms`, is defined to allow peers to advertise support for two distinct categories of signature algorithms, for example, classical and post-quantum.

### Structure

The structure of the extension as follows:

~~~~~~~~~~ ascii-art
struct {
    SignatureScheme first_signature_algorithms<2..2^16-2>;
    SignatureScheme second_signature_algorithms<2..2^16-2>;
} DualSignatureSchemeList;
~~~~~~~~~~
{: title="Contents of dual_signature_algorithms extension"}

SignatureScheme is a 2-octet value identifying a supported signature algorithm as defined in TLS SignatureScheme IANA registry. `first_signature_algorithms` and `second_signature_algorithms` list MUST NOT contain common elements. TLS endpoint observing such overlap between primary and secondary supported signature lists MUST terminate the connection with `illegal_parameter` alert.

### Use in Handshake and Exported Authenticator Messages

The client MAY include this extension in `ClientHello` message to indicate the different categories of algorithms it supports for verifying the server's signature. The server MAY include this extension in `CertificateRequest` message to indicate the different categories of algorithms it supports for verifying the client's signature. This extension MAY be included in an Authenticator Request by the requestor to signal support for dual certificates in the response.

If the extension is present in `ClientHello`, `CertificateRequest` or Authenticator Request, the peer MAY respond with a dual-certificate authentication structure. If the extension is absent, the peer MUST NOT send a two certificate chains or two signatures.

The presence of this extension alone does not mandate dual authentication. It is up to the peer to determine whether one or two certificate chains and signatures are required based on local policy and validation logic. A single certificate and a single signature encoded in `Certificate` and `CertificateVerify` messages remain valid as long as the certificate and its corresponding signature algorithm comply with the values in the `signature_algorithms` or `signature_algorithms_cert` extension.

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

The delimiter is a zero-length certificate entry encoded as 3 bytes of 0x00. TLS 1.3 prohibits empty certificate entries, so this delimiter is unambiguous. The delimiter MUST NOT be sent to peers that did not indicated support for dual certificates by including `dual_signature_algorithms` extension.

This specification expands CertificateEntry structure from {{Section 4.4.2 of TLS}} in the following way:

~~~~~~~~~~ ascii-art
struct {
    select (is_delimiter) {
        case Delimiter: uint24 delimiter = 0;
        case Non_Delimiter:
          select (certificate_type) {
              case RawPublicKey:
                /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
                opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

              case X509:
                opaque cert_data<1..2^24-1>;
          };
          Extension extensions<0..2^16-1>;
    };
} CertificateEntry;
~~~~~~~~~~
{: title="Updated CertificateEntry structure definition"}

All entries before the delimiter are treated as the first certificate chain and MUST use algorithms from `first_signature_algorithms` list of `dual_signature_algorithms` extension (for example classical algorithms), all entries after the delimiter are treated as the second certificate chain and MUST use algorithms from `second_signature_algorithms` list of `dual_signature_algorithms` extension (for example PQC algorithms). As specified in {{Section 4.4.2 of TLS}}, end-entity certificate MUST be the first in both chains.

A peer receiving this structure MUST validate each chain independently according to its corresponding signature algorithm. The end-entity certificate MUST be the first entry in both the first and second certificate chains. The first certificate chain MUST contain certificates whose public key is compatible with one of the algorithms listed in the `first_signature_algorithms` section of `dual_signature_algorithms` extension. The second certificate chain MUST contain certificates whose public key is compatible with one of the algorithms listed in the `second_signature_algorithms` section of `dual_signature_algorithms` extension.

This encoding applies equally to the `CompressedCertificate` message and to `Certificate` message of Exported Authenticators.

## CertificateVerify Message {#certificate-verify}

The `CertificateVerify` message is extended to carry two independent signatures. Its modified structure is as follows:

~~~~~~~~~~ ascii-art
struct {
    SignatureScheme first_algorithm;
    opaque first_signature<0..2^16-1>;
    SignatureScheme second_algorithm;
    opaque second_signature<0..2^16-1>;
} CertificateVerify;
~~~~~~~~~~
{: title="CertificateVerify message"}

Each signature covers the transcript hash as in TLS 1.3, but with a distinct context string for domain separation.

### Context Strings

The context string is used as input to the data over which the signature is computed, consistent with the `CertificateVerify` construction defined in {{Section 4.4.3 of TLS}}. The first signature uses the same context string as in the TLS 1.3 specification:

- for a server context string is "TLS 1.3, server CertificateVerify"
- for a client context string is "TLS 1.3, client CertificateVerify"

The second signature uses a distinct context string to bind it to the secondary certificate:

- for a server, secondary context string is "TLS 1.3, server secondary CertificateVerify"
- for a client, secondary context string is "TLS 1.3, client secondary CertificateVerify"

Implementations MUST verify both signatures and MUST associate each with its corresponding certificate chain.

This dual-signature structure applies equally to `CertificateVerify` messages carried in Exported Authenticators with second signature using "Secondary Exported Authenticator" as the context string.

## Dual Certificate Policy Enforcement

Policy enforcement regarding the use of dual certificates is implementation-defined and driven by the authenticating peer. When dual certificate authentication is required by local policy, such as during high-assurance sessions or post-quantum transition periods, the authenticating endpoint MUST abort a handshake where only one signature or one certificate chain is present with an `dual_certificate_required` alert. Implementations MUST ensure that both certificates and both signatures are processed together and MUST NOT accept fallback to single-certificate authentication when dual-authentication is expected.

A single composite certificate chain and signature such as defined by {{?TLS-COMPOSITE-MLDSA=I-D.tls-reddy-composite-mldsa}} MAY be an acceptable alternative during post-quantum transition period as long as corresponding signature scheme is listed in `signature_algorithms` extension.

# Performance Considerations

The use of dual certificates increases the size of individual certificates, certificate chains, and associated signatures, which can result in significantly larger TLS handshake messages. These larger payloads may cause packet fragmentation, retransmissions, and handshake delays, especially in constrained or lossy network environments.

To mitigate these impacts, deployments can apply certificate chain optimization techniques, such as those described in {{Section 6.1 of ?PQ-RECOMMEND=I-D.reddy-uta-pqc-app}}, to minimize transmission overhead and improve handshake robustness.

# Client-Driven Authentication Requirements

The scenarios in this section describe server authentication behavior based on client policy. Each case reflects a different client capability and authentication policy, based on how the client populates the `signature_algorithms`, `signature_algorithms_cert`, and `dual_signature_algorithms` extensions.

For client authentication, the same principles apply with roles reversed: the server drives authentication requirements by sending a `CertificateRequest` message that includes appropriate extensions.

## Type 1: Single-certificate

Client requires only one classical, pq or a composite signature. Client does not support dual certificates.

Client behavior:

- Includes supported algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Does not include `dual_signature_algorithms`.

To satisfy this client, the server MUST send a single certificate chain with compatible algorithms and include a single signature in `CertificateVerify`.

## Type 2: Dual-Compatible, PQ Optional (Classic Primary)

Client supports both classical and PQ authentication. It allows the server to send either a classical chain alone or both chains.

Client behavior:

- Includes supported classical algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Includes supported classical algorithms in `first_signature_algorithms` list of `dual_signature_algorithms` and supported PQ algorithms in `second_signature_algorithms` list of `dual_signature_algorithms`.

To satisfy this client, the server MUST either:

- Provide a single certificate chain with compatible classical algorithms and include a single signature in `CertificateVerify`
- Provide a classical certificate chain followed by a PQ certificate chain as described in {{certificate}} and two signatures in `CertificateVerify` as described in {{certificate-verify}}

## Type 3: Strict Dual

Client requires both classical and PQ authentication to be performed simultaneously. It does not support composite certificates.

Client behavior:

- Includes an empty list in `signature_algorithms`.
- Includes supported classical algorithms in `first_signature_algorithms` list of `dual_signature_algorithms` and supported PQ algorithms in `second_signature_algorithms` list of `dual_signature_algorithms`.

To satisfy this client, the server MUST provide a classical certificate chain followed by a PQ certificate chain as described in {{certificate}} and two signatures in `CertificateVerify` as described in {{certificate-verify}}

## Type 4: Dual-Compatible, Classic Optional (PQ Primary)

Client supports both classical and PQ authentication. It allows the server to send either a PQ chain alone or both chains.

Client behavior:

- Includes supported PQ algorithms in `signature_algorithms` and optionally `signature_algorithms_cert`.
- Includes supported classical algorithms in `first_signature_algorithms` list of `dual_signature_algorithms` and supported PQ algorithms in `second_signature_algorithms` list of `dual_signature_algorithms`.

To satisfy this client, the server MUST either:

- Provide a single certificate chain with compatible PQ algorithms and include a single signature in `CertificateVerify`
- Provide a PQ certificate chain followed by a classical certificate chain as described in {{certificate}} and two signatures in `CertificateVerify` as described in {{certificate-verify}}

## Compatibility with composite certificates

Clients and servers may choose to support composite certificate schemes, such as those defined in {{TLS-COMPOSITE-MLDSA}}. In these schemes, a single certificate contains a composite public keys, and the associated signature proves knowledge of private keys of all components.

If a composite signature algorithm appears in the `signature_algorithms` extension, it can fulfill the client's requirements for both classical and PQ authentication in a single certificate and signature. It is up to the client policy to decide whether a composite certificate is acceptable in place of a dual-certificate configuration. This allows further deployment flexibility and compatibility with hybrid authentication strategies.

#  Security Considerations

## Signature Association and Parsing Robustness

Implementations MUST strictly associate each `CertificateVerify` signature with the corresponding certificate chain, based on their order relative to the zero-length delimiter in the `Certificate` message. Failure to properly align signatures with their intended certificate chains may result in incorrect validation or misattribution of authentication.

Certificate parsing logic MUST reject messages that contain more than one zero-length delimiter, or that place the delimiter as the first or last entry in the certificate list.

## Signature Validation Requirements

Both signatures in the `CertificateVerify` message MUST be validated successfully and correspond to their respective certificate chains. Implementations MUST treat failure to validate either signature as a failure of the authentication process. Silent fallback to single-certificate verification undermines the dual-authentication model and introduces downgrade risks.

## Side-Channel Resistance

Since both `CertificateVerify` operations involve signing the transcript using different cryptographic primitives, care MUST be taken to avoid leaking side-channel information. Implementers MUST ensure constant-time execution and avoid conditional branching that could reveal whether one or both signatures are present or valid.

Distinct context strings are REQUIRED for the two signatures to prevent cross-protocol misuse or collision attacks.

## Cryptographic Independence

To achieve the intended security guarantees, implementers and deployment operators MUST ensure that the two certificate chains rely on cryptographically independent primitives.

## Certificate Usage and Trust

Certificate chains must be validated independently, including trust anchors, certificate usage constraints, expiration, and revocation status. Operators MUST ensure that revocation checking, such as using OCSP or CRLs, is consistently applied to both chains to prevent reliance on revoked credentials.

#  IANA Considerations

This specification registers the `dual_signature_algorithms` TLS extension and `dual_certificate_required` TLS alert.

## TLS extension

IANA is requested to assign a new value from the TLS ExtensionType Values registry:

 *  Extension Name: dual_signature_algorithms
 *  TLS 1.3: CH, CR
 *  DTLS-Only: N
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

We would like to thank Suzanne Wibada (Université de Sherbrooke) for her reviews and comments during the work on the initial version of this document, and her willingness to implement the recommendation of this document.

--- back

# Informal Requirements for Dual TLS Certificate Support {#sec-design-requirements}

This section documents the design requirements that drove the development of this specification.

This section is primarily intended to easy WG review and could be removed or simplified prior to RFC publication.

## Dual-Algorithm Security

### Weak Non-Separability

The dual certificate authentication achieves, at least, Weak Non-Separability {{?Signature-Spectrums=I-D.ietf-pquip-hybrid-signature-spectrums-06}} at the time of verification of the `CertificateVerify` message.


## Dual Certificate Semantics

### Independent Chain Usability

Each certificate chain (e.g., classic and PQ) must be independently usable for authentication, allowing endpoints to fall back to classic or PQ-only validation if necessary.

### Unambiguous Chain Separation

The mechanism must clearly distinguish and delimit multiple certificate chains to prevent ambiguity or misinterpretation.

## Use Case and Deployment Flexibility

### Backward Compatibility

When only one certificate chain is used, the mechanism must remain compatible with existing TLS 1.3 endpoints unaware of dual-certificate support or willing to use only a single certificate.

### Forward Compatibility

The mechanism must be capable of negotiating algorithms requiring dual certificates as well as algorithms that are acceptable standalone.

As an example, the mechanism must be capable of expressing the following algorithm preference:

> I would accept SLH-DSA-128s, Composite_MLDSA65_RSA2048 Composite_MLDSA65_ECDSA-P256, or ML-DSA-87 by themselves, or a dual-cert hybrid with one of \[ML-DSA-44, ML-DSA-65\] with one of \[RSA, ECDSA-P256, ECDSA-P384\].

### Negotiation Expressiveness

Signature algorithm negotiation, whether single or dual, must arrive at a unique selection of algorithms if and only if there is at least one configuration that is mutually-acceptable to client and server. Specifically, the negotiation mechanism must be expressive enough that clients can list all valid configurations that they would accept. Conversely, the negotiation mechanism must be specific enough that the client is not forced, through clumsiness of the negotiation mechanism to list configurations that in fact it does not support and thus rely on failures and retries to arrive at an acceptable algorithm selection.

### Mitigation of Side Channels

The mechanism should avoid constructions that enable side-channel attacks by observing how distinct algorithms are applied to the same message.

_MikeO: I have never seen this particular side-channel attack described in the literature, so I think a reference is needed. Also, side-channels is a very wide field, so it seems odd to pick out only a very specific type of side-channels to mention. I suggest removing this section._

### Non-ambiguity of Message Formats

The order and pairing between certificates and their corresponding signatures must be explicit, so verifiers can unambiguously match them.

## Interaction With Existing TLS Semantics

### Protocol Flow Consistency

Dual certificate authentication must follow the same logical flow as standard TLS certificate authentication, including integration with `Certificate`, `CertificateVerify`, and `Finished` messages.

### mTLS support

The mechanism must support both server and client authentication scenarios. In case of mutual authentication dual certificates may be used unidirectionally as well as bidirectionally.

### Exported Authenticators Compatibility

The mechanism must be usable with Exported Authenticators (RFC 9261) for mutual authentication in post-handshake settings.


### Minimal Protocol Changes

Any additions or modifications to the TLS protocol must be minimal to ease deployment, reduce implementation complexity and minimize new security risks.

This requirement favours a design which minimizes interaction with other TLS extensions -- ie where all other extensions related to certificates will transfer their semantics from a single-certificate to a dual-certificate setting in a trivial and obvious way and no special processing rules need to be described. Ditto for existing IANA registries relating to the TLS protocol.


## Non-Goals

The following are listed as non-goals; i.e. they are out-of-scope and will not be considered in the design of dual certificate authentication.

### Multiple Identities

This mechanism is specific to cryptographic algorithm migration. It is not a generic mechanism for using multiple identities in a single TLS handshake. In particular, this mechanism does not allow for negotiating two certificates with the same algorithm but containing different identifiers, or for negotiating two independent sets of `certificate_authorities`.
