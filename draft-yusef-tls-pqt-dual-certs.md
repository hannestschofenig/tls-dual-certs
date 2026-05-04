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

The anticipated emergence of cryptographically relevant quantum
computers (CRQCs) poses a threat to the authentication mechanisms used
in TLS 1.3. This document defines a hybrid authentication mechanism
that uses two independent certificates, one traditional and one
post-quantum, ensuring that an attacker must break both algorithms to
compromise a TLS connection. The two certificate chains are carried in a
single `Certificate` message and two independent signatures are encoded
in the `CertificateVerify` message.

--- middle

#  Introduction

There are several potential mechanisms to address concerns related to
the anticipated emergence of cryptographically relevant quantum
computers (CRQCs). While the encryption-related aspects are covered in
other documents, this document focuses on the authentication component
of the {{!TLS=I-D.ietf-tls-rfc8446bis}} handshake.

One approach is the use of dual certificates: issuing two distinct
certificates for the same end entity — one using a traditional
algorithm (e.g., {{?ECDSA=DOI.10.6028/NIST.FIPS.186-5}}), and the
other using a post-quantum (PQ) algorithm (e.g.,
{{?ML-DSA=I-D.ietf-tls-mldsa}}).

This document defines how TLS 1.3 can utilize such certificates to
enable dual-algorithm authentication, ensuring that an attacker would
need to break both algorithms to compromise the session.

It also addresses the challenges of integrating hybrid authentication
in TLS 1.3 while balancing backward compatibility, forward security,
and deployment practicality.

This method exemplifies a PQ/T hybrid protocol with non-composite
authentication as defined in {{Section 4 of
?PQT-TERMS=I-D.ietf-pquip-pqt-hybrid-terminology}}, where two
single-algorithm schemes are used in parallel: when the certificate
type is X.509, each certificate chain uses the same format as in
standard PKI, and both chains together provide hybrid assurance without
modifying the X.509 certificate structure. While this approach does not
produce a single cryptographic hybrid signature, it ensures that both
certificates are presented, validated, and cryptographically bound to
the TLS handshake transcript. This specification is also compatible
with other certificate types defined in the TLS Certificate Types
registry defined in {{Section 14 of ?IANA-TLS=RFC8447}} provided that
both components of the dual are of the same type. This document assumes
X.509 certificates for all explanatory text.

This document defines new `SignatureScheme` code points that identify
pairs of traditional and post-quantum signature algorithms. Negotiation
uses the existing `signature_algorithms` extension without modification.
When a dual code point is selected, the `Certificate` message carries
two independent certificate chains, and the `CertificateVerify`
`signature` field encodes two independent signatures. No new TLS
extensions or changes to existing TLS structures are required.

A key advantage of defining explicit code points per algorithm pair is
that it restricts combinations to known good configurations. This
follows the emerging consensus in protocol design that explicit
enumeration of vetted pairs is safer than allowing arbitrary
combinations of any two algorithms. Each code point defined in this
document represents a specific, vetted pair of traditional and
post-quantum algorithms.

This document is distinct from the composite ML-DSA approach defined
in {{?TLS-COMPOSITE-MLDSA=I-D.tls-reddy-composite-mldsa}}. In that
approach, a single composite certificate contains both public keys and
produces a single composite signature. In this document, two
independent certificates and two independent signatures are used, each
verifiable on its own.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Scope

The approach described herein is also compatible with FIPS-compliant
deployments (FIPS 140-2 and FIPS 140-3), as it supports the continued
use of FIPS-approved traditional signature algorithms during the TLS
handshake.

The proposed mechanism is fully backward compatible: traditional
certificates and authentication methods remain functional with existing
TLS 1.3 implementations. As cryptographically relevant quantum
computers (CRQCs) emerge, deployments can transition by gradually
disabling traditional authentication and enabling post-quantum-only
authentication. This strategy offers a smooth migration path, ensuring
long-term cryptographic agility, regulatory compliance, and operational
continuity without disrupting existing infrastructure.


# Design Overview

This document introduces new `SignatureScheme` code points to enable
dual-certificate authentication in TLS 1.3. The primary objective is
to allow each TLS peer to present two certificate chains requiring an
attacker to break both authentication algorithms to impersonate a peer.
Typically one of the certificate chains uses a traditional cryptographic
algorithm while the second leverages post-quantum (PQ) cryptography.

The design requires no changes to existing TLS structures or
extensions. It reuses the existing `signature_algorithms` extension for
negotiation, the existing `Certificate` message structure with a
delimiter to carry two chains, and the existing `CertificateVerify`
structure with a defined encoding for two signatures within the
`signature` opaque field. It is applicable to both client and server
authentication and is compatible with the Exported Authenticators
mechanism {{!EXPORTED-AUTH=RFC9261}}.

A full set of informal design requirements for this specification can
be found in {{sec-design-requirements}}.

## Signature Algorithms Negotiation

Dual code points are advertised and negotiated using the existing
`signature_algorithms` extension defined in {{Section 4.2.3 of TLS}},
exactly as for any other `SignatureScheme`. A client that supports dual
authentication includes the relevant dual code points in its
`signature_algorithms` list. The server selects one code point from
the client's list, just as in standard TLS 1.3 negotiation.

A client that wishes to mandate dual authentication includes only dual
code points in `signature_algorithms`. A client willing to accept
either dual or single-algorithm authentication includes both dual and
single-algorithm code points.

## Certificate Chain Encoding

TLS 1.3 defines the `Certificate` message to carry a list of
certificate entries representing a single chain. This document reuses
the same structure to convey two certificate chains by concatenating
them and inserting a delimiter in the form of a zero-length certificate
entry.

A zero-length certificate is defined as a `CertificateEntry` with an
empty `cert_data` field and omitted `extensions` field. TLS 1.3
prohibits the use of empty certificate entries, making this delimiter
an unambiguous boundary between the two certificate chains.
Implementations MUST treat all entries before the zero-length delimiter
as the first certificate chain (typically traditional), and all entries
after it as the second certificate chain (typically post-quantum).

This encoding applies equally to the `CompressedCertificate` message
defined in {{?COMPRESS-CERT=RFC8879}} and to the `Certificate` message
of Exported Authenticators as defined in {{Section 5.2.1 of
EXPORTED-AUTH}}.

Since TLS 1.3 supports only a single certificate type in each
direction, both certificate chains MUST either contain X.509
certificates or certificates of type specified in:

- `server_certificate_type` extension in a `EncryptedExtensions`
  message for Server certificates
- `client_certificate_type` extension in a `EncryptedExtensions`
  message for Client certificates

Note that according to {{Section 5.2.1 of EXPORTED-AUTH}} Exported
Authenticators support only X.509 certificates.

## CertificateVerify Signatures

The `CertificateVerify` message is not modified. When a dual code point
has been negotiated, the `signature` field encodes two independent
signatures:

1. One computed using the traditional algorithm component of the
   negotiated code point.
1. One computed using the post-quantum algorithm component of the
   negotiated code point.

Each signature is computed over the transcript hash as specified in
TLS 1.3, using the same context strings defined in
{{Section 4.4.3 of TLS}}. Domain separation between the two signatures
is provided by the distinct certificate chain inputs over which they
are computed.

This encoding applies equally to the `CertificateVerify` message of
Exported Authenticators as defined in {{Section 5.2.2 of EXPORTED-AUTH}}.

The order of the signatures in the message MUST correspond to the order
of the certificate chains in the `Certificate` message: the first
signature MUST correspond to the traditional algorithm component of the
negotiated code point, and the second signature MUST correspond to the
post-quantum algorithm component.

## Common Chains

In order to lessen operational burden on Certification Authority (CA)
operators, the two certificates of the dual MAY be issued from the
same CA. For example, during the PQC migration, a CA operator might
wish to stand up a root CA using a Level 5 PQC algorithm or a
hash-based signature, and then continue to issue RSA and ECDSA
certificates off that root.

Negotiation of such a setup requires use of the
`signature_algorithms_cert` TLS 1.3 extension, which is unmodified
from its definition in {{Section 4.2.3 of TLS}} and when present it
applies equally to both chains of the dual.

In order to optimize bandwidth and avoid sending duplicate copies of
the same chain, when constructing a `Certificate` message as described
in {{certificate}}, the second certificate chain MAY consist of only
an end-entity certificate.

# Protocol Changes

This section defines the normative behaviour of TLS 1.3 peers when a 
dual code point is negotiated. No new TLS extensions or
modifications to existing TLS structures are introduced. This document
defines new `SignatureScheme` code points that, when negotiated, govern
the encoding of the `Certificate` and `CertificateVerify` messages.

## SignatureScheme Code Points {#sec-codepoints}

This document defines new `SignatureScheme` values for use in the
`signature_algorithms` and `signature_algorithms_cert` extensions
defined in {{Section 4.2.3 of TLS}}:

~~~
enum {
    ecdsa_secp256r1_sha256_mldsa44 (TBD1),
    ecdsa_secp384r1_sha384_mldsa65 (TBD2),
} SignatureScheme;
~~~
{: title="Dual SignatureScheme code points"}

Each code point identifies a vetted pair of algorithms: a traditional
algorithm and a post-quantum algorithm. The traditional component names
match the existing TLS SignatureScheme IANA registry entries exactly.
The naming order `<traditional>_<pq>` reflects the order in which the
two signatures appear in the `CertificateVerify` `signature` field, as
defined in {{certificate-verify}}.

These code points are distinct from the composite ML-DSA
`SignatureScheme` values defined in
{{?TLS-COMPOSITE-MLDSA=I-D.tls-reddy-composite-mldsa}}, which use a
single certificate and a single composite signature, and which use the
opposite naming order `<pq>_<traditional>`.

When a code point defined in this document is negotiated, the
authenticating peer MUST send two certificate chains in the
`Certificate` message as described in {{certificate}}, and MUST encode
two independent signatures in the `signature` field of the
`CertificateVerify` message as described in {{certificate-verify}}.

These code points MUST NOT be used in TLS 1.2. A peer that receives a
`CertificateVerify` message in a TLS 1.2 connection with a code point
defined in this document MUST abort the connection with an
`illegal_parameter` alert.

## Certificate Message Encoding {#certificate}

TLS 1.3 defines the `Certificate` message as follows:

~~~~~~~~~~ ascii-art
struct {
    opaque certificate_request_context<0..2^8-1>;
    CertificateEntry certificate_list<0..2^24-1>;
} Certificate;
~~~~~~~~~~
{: title="TLS 1.3 Certificate message"}

This document re-uses the `Certificate` structure as-is and extends
the semantics of `certificate_list` to support two logically distinct
certificate chains, encoded sequentially and separated by a delimiter.

In order to support bandwidth optimization in the case that the two
certificates are issued by the same CA, the second certificate chain
MAY consist of only an end-entity certificate. In this case, validators
SHOULD attempt to validate the second certificate using the chain
provided with the first certificate.

### Delimiter

The delimiter is a zero-length certificate entry encoded as 3 bytes of
0x00. TLS 1.3 prohibits empty certificate entries, so this delimiter
is unambiguous. The delimiter MUST NOT be sent to peers that did not
negotiate a dual code point.

This specification expands the CertificateEntry structure from
{{Section 4.4.2 of TLS}} in the following way:

~~~~~~~~~~ ascii-art
struct {
    select (is_delimiter) {
        case Delimiter: uint24 delimiter = 0;
        case Non_Delimiter:
          opaque cert_specific_data<1..2^24-1>;
          Extension extensions<0..2^16-1>;
    };
} CertificateEntry;
~~~~~~~~~~
{: title="Updated CertificateEntry structure definition"}

Certificate parsing logic MUST reject messages that contain more than
one zero-length delimiter, or that place the delimiter as the first or
last entry in the certificate list. 

All entries before the delimiter are treated as the first certificate
chain (traditional) and MUST use the traditional algorithm component
of the negotiated code point. All entries after the delimiter are
treated as the second certificate chain (post-quantum) and MUST use
the post-quantum algorithm component of the negotiated code point. As
specified in {{Section 4.4.2 of TLS}}, the end-entity certificate MUST
be the first in both chains.

A peer receiving this structure MUST validate each chain independently
according to its corresponding signature algorithm. Implementers MAY
wish to consider performing this verification in a timing-invariant way
so as not to leak which certificate failed, for example if it failed
for policy reasons rather than cryptographic reasons, however since
this information is not hidden in a single-certificate TLS handshake,
implementers MAY decide that this is not important.

The first certificate chain MUST contain an end-entity certificate
whose public key is compatible with the traditional algorithm component
of the negotiated code point. The second certificate chain MUST contain
an end-entity certificate whose public key is compatible with the
post-quantum algorithm component of the negotiated code point.
End-entity certificates of both chains MUST use different public keys.

If a `signature_algorithms_cert` extension is absent, then all
certificates of a given chain MUST also use an algorithm consistent
with its component of the negotiated code point, but not necessarily
the same one as the end-entity certificate. It is always allowed to
provide mixed-algorithm certificate chains within the same component
as long as the relevant algorithms are acceptable.

This encoding applies equally to the `CompressedCertificate` message
and to `Certificate` message of Exported Authenticators.

## CertificateVerify Message {#certificate-verify}

TLS 1.3 defines the `CertificateVerify` message as follows:

~~~
struct {
     SignatureScheme algorithm;
     opaque signature<0..2^16-1>;
} CertificateVerify;
~~~
{: title="TLS 1.3 CertificateVerify message"}

This document does not modify this structure. When a code point defined
in {{sec-codepoints}} has been negotiated, the `algorithm` field
carries that code point and the `signature` field encodes two
independent signatures as follows: the first two bytes encode the length 
of the traditional signature as a uint16, followed by the traditional 
signature (first_signature) of that length, followed by the post-quantum 
signature (second_signature) occupying the remaining bytes.

where:

- `first_signature` is computed using the traditional algorithm
  component of the negotiated code point, over the signing input
  constructed as specified in {{Section 4.4.3 of TLS}}, with the
  `Certificate` input consisting of all entries up to but not including
  the delimiter.

- `second_signature` is computed using the post-quantum algorithm
  component of the negotiated code point, over the signing input
  constructed as specified in {{Section 4.4.3 of TLS}}, with the
  `Certificate` input consisting of all entries after the delimiter.

The context strings used in the signing input are unchanged from
{{Section 4.4.3 of TLS}}. Domain separation between the two signatures
is provided by the distinct certificate chain inputs over which they
are computed.

The receiver MUST verify both signatures. Failure to verify either
signature MUST be treated as an authentication failure and MUST cause
the connection to be aborted with a `decrypt_error` alert.

This encoding applies equally to the `CertificateVerify` message of
Exported Authenticators {{Section 5.2.2 of EXPORTED-AUTH}}.

## Dual Certificate Policy Enforcement

Policy enforcement regarding the use of dual certificates is
implementation-defined and driven by the authenticating peer. When
dual certificate authentication is required by local policy, the client
MUST include only dual code points in `signature_algorithms`. A server
that cannot satisfy this will be unable to complete the handshake.

When a client is willing to accept either dual or single-algorithm
authentication, it MAY include both dual code points and
single-algorithm schemes in `signature_algorithms`.

A single composite certificate chain and signature such as defined by
{{?TLS-COMPOSITE-MLDSA=I-D.tls-reddy-composite-mldsa}} MAY be an
acceptable alternative during the post-quantum transition period as
long as the corresponding signature scheme is listed in
`signature_algorithms`.

Additional policy examples are given in {{sec-policy-examples}}.

# Performance Considerations

The use of dual certificates increases the size of the certificate and
certificate verify messages, which can result in larger TLS handshake
messages. These larger payloads may cause packet fragmentation,
retransmissions, and handshake delays, especially in constrained or
lossy network environments.

To mitigate these impacts, deployments can apply certificate chain
optimization techniques, such as those described in {{Section 6.1 of
?PQ-RECOMMEND=I-D.reddy-uta-pqc-app}}, to minimize transmission
overhead and improve handshake robustness.

#  Security Considerations

## Weak Non-Separability

This dual certificate scheme achieves Weak Non-Separability as defined
in {{?HYBRID-SIGS=I-D.ietf-pquip-hybrid-signature-spectrums}}, which
is defined as:

> the guarantee that an adversary cannot simply "remove" one of the
> component signatures without evidence left behind.

As defined in {{Section 4.4 of TLS}}, `CertificateVerify` contains
signatures over the value `Transcript-Hash(Handshake Context,
Certificate)`. In the dual certificate context, `Certificate` will
contain both certificate chains, which is sufficient to cause the
client to abort and therefore achieves Weak Non-Separability.

## Signature Validation Requirements

Implementations MUST strictly associate each signature in the
`CertificateVerify` `signature` field with the corresponding
certificate chain, based on their order relative to the zero-length
delimiter in the `Certificate` message. Failure to properly align
signatures with their intended certificate chains could result in
incorrect validation or misattribution of authentication.

Both signatures in the `CertificateVerify` message MUST be validated
successfully and correspond to their respective certificate chains.
Implementations MUST treat failure to validate either signature as a
failure of the authentication process. Silent fallback to
single-certificate verification undermines the dual-authentication
model and introduces downgrade risks. Implementations MAY short-circuit
if the first signature or certificate chain fails, or MAY process both
regardless to achieve timing invariance if the implementer deems it
valuable to hide which signature or certificate validation failed, for
example if one of the certificates was rejected for policy reasons
rather than cryptographic reasons.

## Side-Channel Resistance

Some implementations MAY wish to treat a dual signature as an atomic
signing oracle and thus hide side-channels that would allow an attacker
to distinguish the first algorithm from the second algorithm, for
example if the first signature fails, still perform the second
signature before returning an alert. However, in most cases this does
not have practical value, for example if all algorithms offered as dual
are also offered as single.

## Cryptographic Independence Of The Two Chains

While the two selected end-entity certificates will contain keys of
different algorithms, it is possible for them to have certificate
chains that use the same algorithm. In some cases this could be
perfectly acceptable, for example if both chains are rooted in a
hash-based signature or a composite, or if it is intentional for both
end-entity certificates to chain to the same root.

However, in general to achieve the intended security guarantees of
dual-algorithm protection, implementers and deployment operators SHOULD
ensure that the two certificate chains rely on cryptographically
independent primitives.

## Certificate Usage and Trust

Certificate chains MUST be validated independently with the same logic
as if they were each presented in isolation, including trust anchors,
certificate usage constraints, expiration, and revocation status.

## Preventing Downgrade Attacks

TLS clients that are capable of accepting both traditional-only
certificates and dual certificate configurations may remain vulnerable
to downgrade attacks. In such a scenario, an attacker with access to a
CRQC could forge a valid traditional certificate to impersonate the
server and indicate no support for dual certificates. To mitigate this
risk, clients should progressively phase out acceptance of
traditional-only certificate chains once dual certificate deployment is
widespread and interoperability with legacy servers is no longer
necessary. During the transition period, accepting traditional-only
certificate chains may remain necessary to maintain backward
compatibility with servers that have not yet deployed dual certificates.

#  IANA Considerations

This document requests new entries in the TLS SignatureScheme registry
{{?TLSIANA=RFC8447}}.

| Value | Description                        | Recommended | Reference     |
|-------|------------------------------------|-------------|---------------|
| TBD1  | ecdsa_secp256r1_sha256_mldsa44     | N           | This document |
| TBD2  | ecdsa_secp384r1_sha384_mldsa65     | N           | This document |
{: title="New TLS SignatureScheme values"}

These values are distinct from the composite ML-DSA SignatureScheme
values defined in
{{?TLS-COMPOSITE-MLDSA=I-D.tls-reddy-composite-mldsa}}, which use
a single certificate and a single composite signature.

# Acknowledgments

We would like to thank Suzanne Wibada (Université de Sherbrooke) for
her reviews and comments during the work on the initial version of this
document, and her willingness to implement the recommendation of this
document.

We also want to thank Anthony Hu from WolfSSL for his review and
feedback on the initial version of this draft.


--- back

# Open Design Issues

This section documents open design questions that are not resolved in
this version, and for which the authors wish Working Group input.

This section is for Working Group review, and to be removed before
publication.

## Allow mixed certificate chains?

TLS 1.3 defines `signature_algorithms_cert` to negotiate CA algorithms
separately from end-entity algorithms. In practice this extension is
rarely used, as certificate chains are typically homogeneous (e.g.,
exclusively ECDSA or exclusively RSA).

In a dual-certificate context, both chains MAY be issued from the same
CA, for example an SLH-DSA root issuing both an ECDSA and an ML-DSA
end-entity certificate. When `signature_algorithms_cert` is present,
this document specifies that it applies to both chains. The WG is asked
to confirm this is the desired behaviour, or whether a different
treatment is preferred.

# Informal Requirements for Dual TLS Certificate Support {#sec-design-requirements}

This section documents the design requirements that drove the
development of this specification.

This section is primarily intended to ease WG review and could be
removed or simplified prior to RFC publication.

## Dual-Algorithm Security

### Weak Non-Separability

The dual certificate authentication achieves, at least, Weak
Non-Separability {{?Signature-Spectrums=I-D.ietf-pquip-hybrid-signature-spectrums-06}}
at the time of verification of the `CertificateVerify` message.


## Dual Certificate Semantics

### Independent Chain Usability

Each certificate chain (e.g., traditional and PQ) must be
independently usable for authentication, allowing endpoints to fall
back to traditional or PQ-only validation if necessary.

### Unambiguous Chain Separation

The mechanism must clearly distinguish and delimit multiple certificate
chains to prevent ambiguity or misinterpretation.

## Use Case and Deployment Flexibility

### Backward Compatibility

When only one certificate chain is used, the mechanism must remain
compatible with existing TLS 1.3 endpoints unaware of dual-certificate
support or willing to use only a single certificate.

### Forward Compatibility

The mechanism must be capable of negotiating algorithms requiring dual
certificates as well as algorithms that are acceptable standalone.

### Minimal Protocol Changes

Any additions or modifications to the TLS protocol must be minimal to
ease deployment, reduce implementation complexity and minimize new
security risks.

## Non-Goals

### Multiple Identities

This mechanism is specific to cryptographic algorithm migration. It is
not a generic mechanism for using multiple identities in a single TLS
handshake. In particular, this mechanism does not allow for negotiating
two certificates with the same algorithm but containing different
identifiers, or for negotiating two independent sets of
`certificate_authorities`.

# Compatibility with composite certificates

Clients and servers may choose to support composite certificate
schemes, such as those defined in {{TLS-COMPOSITE-MLDSA}}. In these
schemes, a single certificate contains a composite public key, and the
associated signature proves knowledge of private keys of all
components. However, from the perspective of the TLS protocol, this is
a single certificate producing a single composite signature.

If a composite signature algorithm appears in the `signature_algorithms`
extension, it can fulfill the client's requirements for both traditional
and PQ authentication in a single certificate and signature. It is up
to the client policy to decide whether a composite certificate is
acceptable in place of a dual-certificate configuration. This allows
further deployment flexibility and compatibility with hybrid
authentication strategies.

The advantages of dual certificates over composites are operational
flexibility for both Certification Authority operators and TLS server
and client operators because two CAs and end-entity certificates, one
traditional and one PQ, allow for backward-compatible and dynamic
negotiation of pure traditional, pure PQ, or dual.

The advantages of composites over dual certificates are that the
certificate chains themselves are protected by dual-algorithms, which
can be of great importance in use cases where trust stores are not
easily updatable.

A client may include both composite and dual code points in
`signature_algorithms`, leaving the server to select whichever it can
satisfy.

# Policy Examples {#sec-policy-examples}

This section provides non-normative examples of how a client populates
`signature_algorithms` to express different authentication policies.
For client authentication, the same principles apply with roles
reversed: the server drives requirements via `CertificateRequest`.

## Example 1: Single-certificate

Client requires only one traditional, PQ or a composite signature.
Client either does not support or is not configured to accept dual
certificates.

Client behavior:

- Includes only single-algorithm and/or composite code points in
  `signature_algorithms` and optionally `signature_algorithms_cert`.

To satisfy this client, the server MUST send a single certificate chain
with compatible algorithms and include a single signature in
`CertificateVerify`.

## Example 2: Dual-Compatible, Traditional Primary, PQ Optional

Client supports both traditional and PQ authentication. It allows the
server to send either a traditional chain alone or both chains.

Client behavior:

- Includes both traditional single-algorithm code points and dual code
  points in `signature_algorithms` and optionally
  `signature_algorithms_cert`.

To satisfy this client, the server MUST either:

- Provide a single certificate chain with compatible traditional
  algorithms and include a single signature in `CertificateVerify`, or
- Provide a traditional certificate chain followed by a PQ certificate
  chain as described in {{certificate}} and encode two signatures in
  `CertificateVerify` as described in {{certificate-verify}}.

## Example 3: Strict Dual

Client requires both traditional and PQ authentication to be performed
simultaneously.

Client behavior:

- Includes only dual code points in `signature_algorithms`.

To satisfy this client, the server MUST provide a traditional
certificate chain followed by a PQ certificate chain as described in
{{certificate}} and encode two signatures in `CertificateVerify` as
described in {{certificate-verify}}. If the server cannot satisfy this,
the handshake will fail.

## Example 4: Dual-Compatible, PQ Primary, Traditional Optional

Client supports both traditional and PQ authentication. It allows the
server to send either a PQ chain alone or both chains.

Client behavior:

- Includes both PQ single-algorithm code points and dual code points
  in `signature_algorithms` and optionally `signature_algorithms_cert`.

To satisfy this client, the server MUST either:

- Provide a single certificate chain with compatible PQ algorithms and
  include a single signature in `CertificateVerify`, or
- Provide a traditional certificate chain followed by a PQ certificate
  chain as described in {{certificate}} and encode two signatures in
  `CertificateVerify` as described in {{certificate-verify}}.
