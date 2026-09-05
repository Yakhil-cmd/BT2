### Title
Missing contract-identity binding in `pox-5`'s `grant-signer-key` message hash enables signature replay across redeployed PoX contract versions - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5`'s `grant-signer-key` function verifies an off-chain SIP018 signature whose message hash is built only from `{topic, signer-manager, auth-id}` under a fixed domain `{name: "pox-5-signer", version: "1.0.0", chain-id}`. Nothing in the signed payload identifies the specific contract instance (e.g. `address(this)`/`current-contract`) that will consume it. Because the anti-replay map `used-signer-key-grants` lives in that contract's own on-chain storage, a signature that is valid for `pox-5` is still recoverable to the same pubkey against any future contract (e.g. `pox-6`) that reuses the identical domain name/version and message layout, since the new contract starts with an empty `used-signer-key-grants` map. This is exactly the bug class from the external zNS report: a signature not bound to `address(this)`/registrar can be replayed against a differently-deployed instance of a similar contract.

### Finding Description
`get-signer-grant-message-hash` computes: [1](#0-0) 

The domain `POX_5_SIGNER_DOMAIN` and the message tuple contain only `topic`, `signer-manager`, and `auth-id` (plus `chain-id` in the domain) — no reference to the deploying contract's principal. `grant-signer-key` gates replay solely via the per-contract map `used-signer-key-grants`: [2](#0-1) 

This mirrors the Rust helper that produces the same hash off-chain for signers/tooling: [3](#0-2) 

The Stacks protocol has a documented history of retiring PoX contracts and shipping a new one at each major upgrade (`pox-1` → `pox-2` → `pox-3` → `pox-4` → `pox-5`, each with fresh contract storage). `pox-4` uses the analogous pattern for `signer-key-authorizations`/`used-signer-key-authorizations`, also without an `address(this)` binding: [4](#0-3) 

Because `used-signer-key-grants` (and its `pox-4` analog) is contract-local state, it does not carry over to a freshly-deployed successor contract. If that successor contract reuses the same domain literal `"pox-5-signer"`/`"1.0.0"` and the same message shape (a realistic possibility since the code is copy-derived release over release), any previously captured `signer-sig` for a given `(signer-manager, auth-id)` pair becomes valid again and can be replayed by anyone holding it — including a signer-manager operator who intentionally or unintentionally retained an old grant signature, or a third party who observed one on-chain (the signature is emitted in the `print` event and is also visible in the calldata of the original transaction) — to call `grant-signer-key` on the new contract without a fresh authorization from the signer key holder.

### Impact Explanation
A successful replay lets a `signer-manager` contract obtain `grant-signer-key` on the new PoX contract for a signer key whose holder never signed (or explicitly intended) that authorization for the new deployment — this is a stacking-authorization action never re-consented to by the signer, matching the "unsigned stacking action" impact category. Once granted, `register-signer`/`register-self` flows built on top of `verify-signer-key-grant` can proceed to associate stake with that signer key under a manager relationship the key holder did not approve for the new contract, without requiring the bond/pause admin or the signer's active participation.

### Likelihood Explanation
Exploitability depends entirely on a future PoX contract redeploy reusing the identical `POX_5_SIGNER_DOMAIN`/message-tuple shape, which is a real possibility given each PoX generation in this codebase is a near-copy of its predecessor (as seen by `pox-4`'s and `pox-5`'s structurally identical, unbound message-hash pattern). It requires no privileged role — anyone who has observed or retained a previously-issued `signer-sig` (attacker does not need the signer's private key) can attempt the replay against the successor contract. Likelihood is moderate: it is not exploitable against the currently deployed `pox-5` contract itself (intra-contract replay is already blocked by `used-signer-key-grants`), only against a hypothetical/future redeployment that copies the same domain constants — which is exactly the scenario this contract family has followed historically.

### Recommendation
Bind the `pox-5` (and `pox-4`) signer-grant/signer-key message hashes to the specific contract instance by including `(as-contract tx-sender)` / `current-contract`'s principal (i.e., an `address(this)` analog) in the signed tuple, alongside the existing `chain-id` and `auth-id`. This ensures a signature produced for one deployed PoX contract cannot be recovered as valid against any future contract that happens to reuse the same domain name/version literals.

### Proof of Concept
1. Signer `S` signs a `grant-authorization` message for `signer-manager M` with `auth-id A` under `pox-5`'s domain (`get-signer-grant-message-hash M A`), per [1](#0-0) .
2. `M` calls `grant-signer-key` on `pox-5`; the grant succeeds and `(signer-key, M, A)` is recorded in `pox-5`'s `used-signer-key-grants` map, per [5](#0-4) . The raw `signer-sig` is exposed in the transaction and the `print` event.
3. A future contract `pox-6` is deployed reusing the identical `POX_5_SIGNER_DOMAIN`-style constant and identical `get-signer-grant-message-hash` shape (as `pox-4`→`pox-5` did) with a fresh, empty `used-signer-key-grants` map.
4. Anyone (not necessarily `S` or `M`) resubmits the same `(signer-key, M, A, signer-sig)` tuple to `pox-6`'s `grant-signer-key`. Since the hash recomputed by `pox-6` is byte-identical to the one `S` originally signed (no contract-identity field differs it), `secp256k1-recover?` succeeds and the replay grant is accepted, associating `S`'s signer key with `M` on `pox-6` without any new consent from `S`.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2743-2790)
```text
(define-public (grant-signer-key
        (signer-key (buff 33))
        (signer-manager principal)
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (begin
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Only the signer contract itself can call this function to grant a signer key
        (asserts! (is-eq contract-caller signer-manager)
            ERR_UNAUTHORIZED_SIGNER_REGISTRATION
        )
        (asserts!
            (is-none (map-get? used-signer-key-grants {
                signer-key: signer-key,
                signer-manager: signer-manager,
                auth-id: auth-id,
            }))
            ERR_SIGNER_KEY_GRANT_USED
        )

        (asserts!
            (is-eq
                (unwrap!
                    (secp256k1-recover?
                        (get-signer-grant-message-hash signer-manager auth-id)
                        signer-sig
                    )
                    ERR_INVALID_SIGNATURE_RECOVER
                )
                signer-key
            )
            ERR_INVALID_SIGNATURE_PUBKEY
        )

        (asserts!
            (map-insert used-signer-key-grants {
                signer-key: signer-key,
                signer-manager: signer-manager,
                auth-id: auth-id,
            }
                true
            )
            ERR_SIGNER_KEY_GRANT_USED
        )

```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2862-2877)
```text
;; Construct the message hash for validating a signer key grant. Unlike [get-signer-key-message-hash],
;; this message hash does not include `max-amount`, `period`, or `reward-cycle`. The topic is always `"grant-authorization"`.
;; The `pox-addr` field is optional. When `none`, it means the signer key can be used for any PoX address.
(define-read-only (get-signer-grant-message-hash
        (signer-manager principal)
        (auth-id uint)
    )
    (sha256 (concat SIP018_MSG_PREFIX
        (sha256 (unwrap-panic (to-consensus-buff? POX_5_SIGNER_DOMAIN)))
        (sha256 (unwrap-panic (to-consensus-buff? {
            topic: "grant-authorization",
            signer-manager: signer-manager,
            auth-id: auth-id,
        })))
    ))
)
```

**File:** stackslib/src/util_lib/signed_structured_data.rs (L434-458)
```rust
    /// Compute the hash of the `grant-authorization` message that is signed
    /// by a signer key when authorizing a `signer-manager` contract to
    /// register the corresponding signer via pox-5's `grant-signer-key`.
    pub fn make_pox_5_signer_grant_message_hash(
        signer_manager: &PrincipalData,
        auth_id: u128,
        chain_id: u32,
    ) -> Sha256Sum {
        let domain_tuple = make_pox_5_signed_data_domain(chain_id);
        let data_tuple = Value::Tuple(
            TupleData::from_data(vec![
                (
                    ClarityName::from_literal("topic"),
                    Value::string_ascii_from_bytes("grant-authorization".into()).unwrap(),
                ),
                (
                    ClarityName::from_literal("signer-manager"),
                    Value::Principal(signer_manager.clone()),
                ),
                (ClarityName::from_literal("auth-id"), Value::UInt(auth_id)),
            ])
            .expect("Error creating signature hash"),
        );
        structured_data_message_hash(data_tuple, domain_tuple)
    }
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L687-710)
```text
;; Generate a message hash for validating a signer key.
;; The message hash follows SIP018 for signing structured data. The structured data
;; is the tuple `{ pox-addr: { version, hashbytes }, reward-cycle, auth-id, max-amount }`.
;; The domain is `{ name: "pox-4-signer", version: "1.0.0", chain-id: chain-id }`.
(define-read-only (get-signer-key-message-hash (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                               (reward-cycle uint)
                                               (topic (string-ascii 14))
                                               (period uint)
                                               (max-amount uint)
                                               (auth-id uint))
  (sha256 (concat
    SIP018_MSG_PREFIX
    (concat
      (sha256 (unwrap-panic (to-consensus-buff? { name: "pox-4-signer", version: "1.0.0", chain-id: chain-id })))
      (sha256 (unwrap-panic
        (to-consensus-buff? {
          pox-addr: pox-addr,
          reward-cycle: reward-cycle,
          topic: topic,
          period: period,
          auth-id: auth-id,
          max-amount: max-amount,
        })))))))

```
