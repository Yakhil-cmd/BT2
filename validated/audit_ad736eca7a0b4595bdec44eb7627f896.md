### Title
Malicious Participant Can Corrupt CKD Output by Sending Arbitrary Unvalidated Shares - (File: src/confidential_key_derivation/protocol.rs)

### Summary
In the Confidential Key Derivation (CKD) protocol, the coordinator blindly accumulates `(big_y, big_c)` contributions from every participant with no cryptographic proof that each share is correctly formed. A single malicious participant can inject arbitrary curve points, silently biasing the aggregated output so the requester derives a wrong confidential key with no indication of failure.

### Finding Description
The CKD coordinator path in `do_ckd_coordinator` collects each participant's `(norm_big_y, norm_big_c)` pair and adds them unconditionally:

```rust
// src/confidential_key_derivation/protocol.rs  lines 50-55
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
```

The honest computation each participant is supposed to perform is:

```
norm_big_y = λᵢ