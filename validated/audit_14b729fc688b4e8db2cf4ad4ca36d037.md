### Title
Unverified Participant Contributions in CKD Protocol Allow Any Malicious Participant to Corrupt the Confidential Key Derivation Output — (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary

The CKD coordinator blindly sums every participant's `(big_y, big_c)` contribution with no proof of correctness. A single malicious participant can substitute arbitrary group elements, causing the coordinator to assemble a structurally valid but cryptographically wrong `CKDOutput`. Every honest caller that later calls `unmask` will receive an incorrect derived secret.

---

### Finding Description

`compute_signature_share` is the honest computation each participant is supposed to perform:

```
y  ← random scalar
Y  = y · G
S  = x_i · H(pk ∥ app_id)          // x_i = private share
C  = S + y · app_pk
(norm_Y, norm_C) = (λ_i · Y, λ_i · C)
```

The coordinator aggregates all `