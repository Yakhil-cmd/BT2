### Title
Signer-key authorization is not bound to the committer, letting anyone front-run and permanently burn a `stack-aggregation-commit` authorization intended for another delegate - (File: `stackslib/src/chainstate/stacks/boot/pox-4.clar`)

### Summary
`pox-4`'s signer-key authorization scheme (`signer-sig` / `set-signer-key-authorization` + `auth-id`) is the analog of the Nouns-Builder `proposalId`: it is a single-use, publicly-derivable key that is *not* bound to the transaction sender who is allowed to consume it. Just as an attacker could front-run a `propose()` call and then `cancel()` it to permanently occupy the `proposalId`, an attacker here can front-run a pending `stack-aggregation-commit`/`-indexed` transaction (or a `stack-stx`/`stack-extend` transaction) using the exact same public `signer-sig`, `pox-addr`, `reward-cycle`, `period`, `topic`, `auth-id`, and `max-amount`, but with their own `tx-sender` and a trivially small already-partially-stacked amount. This permanently marks the authorization as used, so the legitimately intended, larger commitment can never be submitted with that authorization again.

### Finding Description
`consume-signer-key-authorization` verifies a signer-key authorization and marks it used in `used-signer-key-authorizations`: [1](#0-0) 

The message hash that is signed by the signer key covers only `pox-addr`, `reward-cycle`, `topic`, `period`, `max-amount`, and `auth-id` — it contains **no reference to `tx-sender`/the committer's identity**: [2](#0-1) 

`verify-signer-key-sig` only checks that the requested `amount` is `<= max-amount` and that the `(signer-key, reward-cycle, topic, period, pox-addr, auth-id, max-amount)` tuple has not been used yet — it never checks who is calling: [3](#0-2) 

`used-signer-key-authorizations` map key likewise omits any `sender`/committer field, so it is a single global "used" flag keyed purely on the authorization's public parameters: [4](#0-3) 

In `inner-stack-aggregation-commit`, `amount-ustx` is derived from the *caller's own* `partial-stacked-by-cycle` entry (keyed by `{pox-addr, reward-cycle, sender: tx-sender}`), and the only constraint tying the authorization to that amount is `amount-ustx <= max-amount`: [5](#0-4) 

Attack sequence (mirrors propose+cancel front-running):
1. A legitimate delegator/pool operator (Bob) has partially stacked a large amount to `pox-addr` for `reward-cycle` via `delegate-stack-stx`/`stack-aggregation-increase` flows, and has a pending `stack-aggregation-commit`/`-indexed` transaction in the mempool carrying a `signer-sig` (or referencing a pre-set `signer-key-authorizations` entry) for `(pox-addr, reward-cycle, "agg-commit", u1, auth-id, max-amount)`.
2. Attacker (Mallory) observes this pending transaction (the `signer-sig`/authorization parameters are public in the mempool, exactly as the proposal data was public in the Nouns-Builder mempool).
3. Mallory first performs `delegate-stx` + `delegate-stack-stx` (or `stack-stx`) with a **minimal** amount to the **same** `pox-addr`/`reward-cycle`, so she has her own `partial-stacked-by-cycle` entry for that key with `amount-ustx <= max-amount`.
4. Mallory calls `stack-aggregation-commit`/`-indexed` with the copied `pox-addr`, `reward-cycle`, `signer-sig`, `signer-key`, `max-amount`, `auth-id`, using her own `tx-sender`. Because `verify-signer-key-sig` never checks who calls, this succeeds, and `consume-signer-key-authorization` sets `used-signer-key-authorizations{...auth-id...}` to `true` permanently (there is no `cancel`/reset function for this map, exactly like `Governor.cancel` leaving `proposal.voteStart != 0` permanently).
5. Bob's original transaction later lands and reverts with `ERR_SIGNER_AUTH_USED`, exactly as `PROPOSAL_EXISTS` blocked the legitimate proposer.

### Impact Explanation
Bob's larger amount was already locked STX (locked earlier via `delegate-stack-stx`/`stack-stx`), but it can never be admitted into `reward-cycle-pox-address-list` for that reward cycle because the one-time authorization the signer produced for that specific commit has been irrevocably consumed by someone else's unrelated, trivial commitment. Since the aggregation-commit window is tied to a specific upcoming reward cycle and the PoX anchor-block deadline, Bob cannot simply re-request the same authorization in time; his STX remain locked for the full lock period but never earn a PoX reward slot for that cycle — a temporary freezing of staked STX with loss of a signed stacking action's intended effect (the signer authorized the commit for a specific committer's amount, not for an arbitrary third party's negligible amount). This matches the High-severity impact category "temporary freezing of staked funds ... a stacking action the staker/signer never authorised" — the signer never intended for an unrelated third party's negligible commitment to consume the authorization.

### Likelihood Explanation
Any account can perform this: it only requires (a) observing public mempool transaction data (signature, `auth-id`, `pox-addr`, `reward-cycle`, `max-amount` are all plaintext arguments), and (b) making a trivially small `delegate-stack-stx`/`stack-stx` commitment to the same `pox-addr`/`reward-cycle` beforehand so the attacker has a qualifying `partial-stacked-by-cycle` entry. No special privilege, admin key, or victim's private key is required — only front-running (higher fee) capability, identical to the original report's assumption.

### Recommendation
Bind the signer-key authorization message hash (and the `used-signer-key-authorizations`/`signer-key-authorizations` map keys) to the specific committer, e.g. include `tx-sender` (or an explicit `committer` field supplied and checked in `consume-signer-key-authorization`) in `get-signer-key-message-hash` and in both authorization maps, so an authorization can only be consumed by the account it was actually issued for. Alternatively, require `amount == max-amount` (or bind the exact expected amount into the signed payload) instead of a loose `<=` bound, so a third party cannot satisfy the check with an unrelated, smaller amount.

### Proof of Concept
1. Signer `S` signs an authorization for `pox-addr = P`, `reward-cycle = C`, `topic = "agg-commit"`, `period = 1`, `max-amount = 1_000_000_000_000`, `auth-id = 42`, intended for delegator `Bob` who has partially stacked `900_000_000_000` uSTX to `P` for cycle `C` via `delegate-stack-stx`.
2. Bob broadcasts `stack-aggregation-commit-indexed(P, C, some(sig), S_pubkey, 1_000_000_000_000, 42)`; it sits in the mempool.
3. Attacker `Mallory` first calls `delegate-stx` then `delegate-stack-stx(Mallory-controlled-stacker, 1, P, ..., C-related start-burn-ht, 1)` to create a `partial-stacked-by-cycle{pox-addr: P, sender: Mallory, reward-cycle: C}` entry of `1` uSTX (satisfies `can-stack-stx`/threshold logic per contract rules, or she uses `stack-aggregation-increase` chain to reach a valid small amount).
4. Mallory copies Bob's pending transaction's exact `(P, C, sig, S_pubkey, 1_000_000_000_000, 42)` arguments and calls `stack-aggregation-commit-indexed` herself with higher gas/fee, landing first.
5. `consume-signer-key-authorization` succeeds for Mallory (her `amount-ustx = 1 <= max-amount`), inserting `{signer-key: S_pubkey, reward-cycle: C, topic: "agg-commit", period: 1, pox-addr: P, auth-id: 42, max-amount: 1_000_000_000_000} -> true` into `used-signer-key-authorizations`.
6. Bob's transaction now fails at `(asserts! (map-insert used-signer-key-authorizations ...) (err ERR_SIGNER_AUTH_USED))` inside `consume-signer-key-authorization`, permanently blocking Bob's large commitment from being admitted into the reward set for cycle `C` using that authorization. [6](#0-5)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L248-262)
```text
;; State for tracking used signer key authorizations. This prevents re-use
;; of the same signature or pre-set authorization for multiple transactions.
;; Refer to the `signer-key-authorizations` map for the documentation on these fields
(define-map used-signer-key-authorizations
    {
        signer-key: (buff 33),
        reward-cycle: uint,
        period: uint,
        topic: (string-ascii 14),
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        auth-id: uint,
        max-amount: uint,
    }
    bool ;; Whether the field has been used or not
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L691-710)
```text
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

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L735-762)
```text
(define-read-only (verify-signer-key-sig (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                         (reward-cycle uint)
                                         (topic (string-ascii 14))
                                         (period uint)
                                         (signer-sig-opt (optional (buff 65)))
                                         (signer-key (buff 33))
                                         (amount uint)
                                         (max-amount uint)
                                         (auth-id uint))
  (begin
    ;; Validate that amount is less than or equal to `max-amount`
    (asserts! (>= max-amount amount) (err ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH))
    (asserts! (is-none (map-get? used-signer-key-authorizations { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
              (err ERR_SIGNER_AUTH_USED))
    (match signer-sig-opt
      ;; `signer-sig` is present, verify the signature
      signer-sig (ok (asserts!
        (is-eq
          (unwrap! (secp256k1-recover?
            (get-signer-key-message-hash pox-addr reward-cycle topic period max-amount auth-id)
            signer-sig) (err ERR_INVALID_SIGNATURE_RECOVER))
          signer-key)
        (err ERR_INVALID_SIGNATURE_PUBKEY)))
      ;; `signer-sig` is not present, verify that an authorization was previously added for this key
      (ok (asserts! (default-to false (map-get? signer-key-authorizations
            { signer-key: signer-key, reward-cycle: reward-cycle, period: period, topic: topic, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
          (err ERR_NOT_ALLOWED)))
    ))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L765-788)
```text
;; This function does two things:
;;
;; - Verify that a signer key is authorized to be used
;; - Updates the `used-signer-key-authorizations` map to prevent reuse
;;
;; This "wrapper" method around `verify-signer-key-sig` allows that function to remain
;; read-only, so that it can be used by clients as a sanity check before submitting a transaction.
(define-private (consume-signer-key-authorization (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                                  (reward-cycle uint)
                                                  (topic (string-ascii 14))
                                                  (period uint)
                                                  (signer-sig-opt (optional (buff 65)))
                                                  (signer-key (buff 33))
                                                  (amount uint)
                                                  (max-amount uint)
                                                  (auth-id uint))
  (begin
    ;; verify the authorization
    (try! (verify-signer-key-sig pox-addr reward-cycle topic period signer-sig-opt signer-key amount max-amount auth-id))
    ;; update the `used-signer-key-authorizations` map
    (asserts! (map-insert used-signer-key-authorizations
      { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount } true)
      (err ERR_SIGNER_AUTH_USED))
    (ok true)))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-4.clar (L802-817)
```text
(define-private (inner-stack-aggregation-commit (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                                (reward-cycle uint)
                                                (signer-sig (optional (buff 65)))
                                                (signer-key (buff 33))
                                                (max-amount uint)
                                                (auth-id uint))
  (let ((partial-stacked
         ;; fetch the partial commitments
         (unwrap! (map-get? partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle })
                  (err ERR_STACKING_NO_SUCH_PRINCIPAL))))
    ;; must be called directly by the tx-sender or by an allowed contract-caller
    (asserts! (check-caller-allowed)
              (err ERR_STACKING_PERMISSION_DENIED))
    (let ((amount-ustx (get stacked-amount partial-stacked)))
      (try! (consume-signer-key-authorization pox-addr reward-cycle "agg-commit" u1 signer-sig signer-key amount-ustx max-amount auth-id))
      (try! (can-stack-stx pox-addr amount-ustx reward-cycle u1))
```
