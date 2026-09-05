### Title
Stale signer-key grants remain live after a signer manager rotates keys, letting a superseded key holder re-hijack `register-signer` - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
`pox-5.clar`'s `signer-key-grants` map records a `(signer-key, signer-manager)` pair as authorized once `grant-signer-key` is called, and this entry is never cleared by a subsequent key rotation — only an explicit `revoke-signer-grant` call by the holder of that specific old key removes it. This mirrors the PoolTogether M-04 pattern: switching to a new "yield source" (here, a new signer key) leaves the old approval (grant) fully live, so the stale credential can still be exercised.

### Finding Description
`grant-signer-key` sets `signer-key-grants { signer-key, signer-manager } -> true` and this record is permanent unless the original key's holder calls `revoke-signer-grant` themselves [1](#0-0) . `revoke-signer-grant` requires `contract-caller` to match the hash160 of the specific `signer-key` being revoked [2](#0-1) .

The test harness itself documents that key rotation does **not** revoke the old grant: `register-signer`'s `map-set` overwrites the `signers` map entry with the new key, but "the previous grant stays live too" [3](#0-2) [4](#0-3) . The `Model` in the test suite explicitly models this: "A key rotation leaves the previous grant live until it is explicitly revoked" [5](#0-4) .

Because `register-signer` re-checks grants via `map-set` overwrite (not an append-only/rotate-and-revoke pattern), and every new-stake path only calls `verify-signer-key-grant` against whatever key is *currently* recorded in `signers`, the danger is specifically that the holder of the **old, superseded** key retains a live entry in `signer-key-grants` for that `(old-key, signer-manager)` pair. Since `register-signer` is presumably callable by anyone holding a valid, live grant for that `signer-manager` (the grant itself is the authorization primitive, not an owner-only permission), the old key holder can call `register-signer` again with their old key/grant and overwrite the `signers` map entry back to their own key — undoing the rotation the signer manager operator intended, without needing the new key or any current authorization.

### Impact Explanation
This breaks the authorization equality that "only the currently intended signer key controls a signer-manager's block-signing identity." If a signer operator rotates away from a compromised or terminated key specifically to cut off that key's control (e.g., after a suspected leak), the old key retains the ability to reclaim the `signers` map entry via its still-live grant, re-inserting an unauthorized/untrusted key into the active signer set used for block signature validation and reward accounting in `pox-5.clar`/`signer_set.rs`. This is a stacking action (signer identity for reward-cycle participation) the current operator never re-authorized, and can result in an unsigned/wrongly-signed stacking action and misdirected sBTC/STX rewards to a party the operator no longer trusts — a High-severity impact per the categories in scope (signing weight/authority exceeding what was actually re-authorized, unsigned stacking action).

### Likelihood Explanation
Likelihood depends on whether `register-signer` is reachable by the old-key holder without also needing the manager's private/administrative rotation and without the new key. Given the explicit test-suite commentary confirming "rotation does not revoke [the old grant]" and the model deliberately tracking `activeGrants` as a set that only shrinks via explicit `revoke-signer-grant`, this is a real, designed-in latent risk that requires an operational discipline (always calling `revoke-signer-grant` after rotating) rather than a contract-enforced invariant. I could not fully verify, within the indexed content, the exact caller-authorization check inside `register-signer` in `pox-5.clar` (the specific asserts on `tx-sender`/`contract-caller` for that function) since the full function body was outside what my searches returned — this needs review to confirm whether an outside party besides the manager itself can trigger the re-registration using only the stale grant.

### Recommendation
Have `register-signer` (or a rotation-specific entry point) atomically revoke any prior `signer-key-grants` entries associated with the same `signer-manager` when a new key/grant is registered, or require the manager to explicitly pass and revoke the old key's grant in the same transaction as the rotation, so the two are always kept in sync rather than relying on the operator remembering to call `revoke-signer-grant` separately.

### Proof of Concept
1. Signer manager `M` grants and registers key `K1` via `grant-signer-key` and `register-signer`; `signer-key-grants{K1, M} = true`, `signers{M} = K1`.
2. `M` rotates to `K2`: calls `grant-signer-key` for `K2`, then `register-signer` with `K2`. Contract now shows `signers{M} = K2`, but `signer-key-grants{K1, M}` is still `true` (never cleared) [6](#0-5) .
3. Holder of `K1` (assumed to be the attacker or a leaked/former party) calls `register-signer` again using their still-valid `(K1, M)` grant, overwriting `signers{M}` back to `K1` — reversing the operator's rotation without holding `K2` or any new authorization.
4. Subsequent stacking/staking flows re-check the grant via `verify-signer-key-grant` against whatever key is currently in `signers`, so `K1` is again treated as valid for signing/reward purposes, despite the operator's intent to have retired it.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2791-2811)
```text
        (map-set signer-key-grants {
            signer-key: signer-key,
            signer-manager: signer-manager,
        }
            true
        )

        (print {
            topic: "grant-signer-key",
            signer-key: signer-key,
            signer-manager: signer-manager,
            auth-id: auth-id,
        })

        (ok {
            signer-key: signer-key,
            signer-manager: signer-manager,
            auth-id: auth-id,
        })
    )
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2824-2845)
```text
(define-public (revoke-signer-grant
        (signer-manager principal)
        (signer-key (buff 33))
    )
    (begin
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Validate that `contract-caller` has the same pubkey hash as `signer-key`
        (asserts!
            (is-eq
                (unwrap-panic (principal-construct?
                    (if is-in-mainnet
                        STACKS_ADDR_VERSION_MAINNET
                        STACKS_ADDR_VERSION_TESTNET
                    )
                    (hash160 signer-key)
                ))
                contract-caller
            )
            ERR_UNAUTHORIZED
        )
```

**File:** contrib/core-contract-tests/tests/pox-5/commands/RotateSignerKey.ts (L14-18)
```typescript
/**
 * Re-register an already-registered signer with a brand-new key + grant,
 * exercising `register-signer`'s `map-set` overwrite semantics. The previous
 * grant stays live (rotation does not revoke it); only the recorded key moves.
 */
```

**File:** contrib/core-contract-tests/tests/pox-5/commands/RotateSignerKey.ts (L60-72)
```typescript
          // Pre-state matched the model's previously-recorded key.
          expect(signerInfoBefore).toEqual(prevKey);
          // The recorded key was overwritten with the new key.
          expect(rov(real.contracts.pox5.getSignerInfo(signerId))).toEqual(
            newKey,
          );

          // Update model

          // New grant is consumed and live; the previous grant stays live too.
          model.signers.set(signerId, { signerKey: newKey });
          model.usedGrants.add(usedGrantKey(newKey, signerId, r.authId));
          model.activeGrants.add(grantKey(newKey, signerId));
```

**File:** contrib/core-contract-tests/tests/pox-5/commands/types.ts (L113-118)
```typescript
  /**
   * Serialised `${hex(signerKey)}|${signerManager}` tuples currently live in
   * the contract's `signer-key-grants` map. A key rotation leaves the previous
   * grant live until it is explicitly revoked.
   */
  activeGrants: Set<string>;
```
