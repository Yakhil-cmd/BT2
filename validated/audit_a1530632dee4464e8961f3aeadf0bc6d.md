### Title
Unvalidated Participant Contributions in CKD Coordinator Allow Corruption of Derived Confidential Key - (File: `src/confidential_key_derivation/protocol.rs`)

---

### Summary
The CKD coordinator in `do_ckd_coordinator` blindly accumulates `(norm_big_y, norm_big_c)` contributions from every participant with no validity checks on the received group elements. A single malicious participant can send arbitrary elliptic-curve points — including the identity — causing the coordinator to output a structurally valid but cryptographically wrong `CKDOutput`, permanently corrupting the derived confidential key for the targeted `app_id`.

---

### Finding Description

In `do_ckd_coordinator`, after computing its own share, the coordinator loops over all other participants' messages and unconditionally adds them:

```rust
for (_, participant_output) in
    recv_from_others::<CKDOutput>(&chan, waitpoint, &participants, me).await?
{
    norm_big_y += participant_output.big_y();
    norm_big_c += participant_output.big_c();
}
let ckd_output = CKDOutput::new(norm_big_y, norm_big_c);
```

No checks are performed on the received values:

1. **No identity-element check** — `big_y` or `big_c` may be the group identity (the additive zero of G1), which silently zeroes out that participant's contribution.
2. **No proof of correct computation** — there is no ZK proof (e.g., a DLOGEQ proof) that the sender actually computed `norm_big_y = λ_i · y_i · G` and `norm_big_c = λ_i · (x_i · H(pk, app_id) + y_i · app_pk)`