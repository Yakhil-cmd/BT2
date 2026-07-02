# Q3358: quic_client_certificate Verification bypass on reachable authenticated input

## Question
Can an unprivileged attacker reach `tls-utils/src/quic_client_certificate.rs::new` with crafted serialized bytes, signature/proof fields, certificate material, and parsing layout so a malformed signature, proof, or certificate is treated as valid or as already verified?

## Target
- File/function: tls-utils/src/quic_client_certificate.rs::new
- Entrypoint: public packet, vote, shred, or transaction carrying authenticated bytes
- Attacker controls: serialized bytes, signature/proof fields, certificate material, and parsing layout
- Exploit idea: Probe parser/validator boundaries, trusted-path metadata, and fallback behavior on malformed authenticated data.
- Invariant to test: No invalid authenticated input should be able to cross a verification boundary or inherit verified status.
- Expected Immunefi impact: Critical. Unintended permanent chain split requiring hard fork (network partition requiring hard fork)
- Fast validation: Fuzz malformed authenticated inputs and assert they are never accepted or tagged as verified.
