# Informal Requirements for Dual TLS Certificate Support
## 1. General TLS Semantics

### 1a. Protocol Flow Consistency

Dual certificate authentication must follow the same logical flow as standard TLS certificate authentication, including integration with `Certificate`, `CertificateVerify`, and `Finished` messages.

### 1b. Minimal Protocol Changes

Any additions or modifications to the TLS protocol must be minimal to ease deployment, reduce implementation complexity and minimize new security risks.

### 1c. mTLS support

The mechanism must support both server and client authentication scenarios. In case of mutual authentication dual certificates may be used unidirectionally as well as bidirectionally.

### 1d. Exported Authenticators Compatibility

The mechanism must be usable with Exported Authenticators (RFC 9261) for mutual authentication in post-handshake settings.

## 2. Certificate Handling Semantics

### 2a. Independent Chain Usability

Each certificate chain (e.g., classic and PQ) must be independently usable for authentication, allowing endpoints to fall back to classic or PQ-only validation if necessary.

### 2b. Unambiguous Chain Separation

The mechanism must clearly distinguish and delimit multiple certificate chains to prevent ambiguity or misinterpretation.

### 2c. Chain-Specific Signature Algorithms

Each certificate chain must be associated with its own set of supported signature algorithms, allowing negotiation of appropriate algorithms for classic and PQ use cases.

### 2d. Multiple Chains Support (Generalisation)

The mechanism must be designed in a way that could support more than two certificate chains in the future, not just hardcoded to classic + PQ.

## 3. Use Case and Deployment Flexibility

### 3a. Backward Compatibility

When only one certificate chain is used, the mechanism must remain compatible with existing TLS 1.3 endpoints unaware of dual-certificate support or willing to use only a single certificate.

### 3b. Policy Signalling

A mechanism must exist for one party (client or server) to signal whether dual certificate presentation is required, optional, or not supported, to coordinate authentication expectations.

### 3c. Support for Non-PQC Multi-Cert Use Cases

The mechanism must be expandable to other multi-certificate use cases such as attested TLS

### 3d. Mitigation of Side Channels

The mechanism should avoid constructions that enable side-channel attacks by observing how distinct algorithms are applied to the same message.

### 3e. Transparency in Signature Validation

The order and pairing between certificates and their corresponding signatures must be explicit, so verifiers can unambiguously match them.