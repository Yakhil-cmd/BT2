The code confirms the anti-replay key is tuple-based, not signature-byte-based.

### Title
No vulnerability - signature malleability does not bypass replay protection in `grant-signer-key` - (File: stackslib/src/chainstate/stacks/boot/pox-5.clar)

### Summary
The question hypothesizes that `used-signer-key-grants` is keyed on raw signature bytes, allowing a malleated (high-S) variant of a previously used signature to bypass `ERR_SIGNER_KEY_GRANT_USED`. Inspection of `grant-signer-key` shows the anti-replay map is keyed strictly on the semantic tuple `{signer-key, signer-manager, auth-id}`, never on the signature bytes themselves, so malleation has no effect on the replay check.

### Finding Description
In `grant-signer-key` [1](#0-0) , the flow is: (1) assert `contract-caller == signer-manager`; (2) assert `used-signer-key-grants` has no entry for `{signer-key, signer-manager, auth-id}` [2](#0-1) ; (3) recover the pubkey from `signer-sig` via `secp256k1-recover?` over `get-signer-grant-message-hash` and assert it equals `signer-key` [3](#0-2) ; (4) `map-insert used-signer-key-grants {signer-key, signer-manager, auth-id} true`, which itself fails (returns `false` → `ERR_SIGNER_KEY_GRANT_USED`) if the tuple already exists [4](#0-3) .

The `used-signer-key-grants` map's key type is `{signer-key: (buff 33), signer-manager: principal, auth-id: uint}` [5](#0-4)  — it is never keyed on `signer-sig`. Since a malleated `signer-sig'` recovers the identical `signer-key`, the second call's lookup at step (2) hits the exact same tuple key already inserted by the first call, and `is-none` evaluates to `false`, so `ERR_SIGNER_KEY_GRANT_USED` fires before `secp256k1-recover?` is even reached. The `map-insert` at step (4) is a second, redundant safeguard that would also reject the duplicate tuple.

There is no path for a malleated encoding to change the tuple key, since `auth-id`, `signer-manager`, and the recovered `signer-key` are all identical regardless of which valid signature encoding is used. The existing test `grant-signer-key rejects replay of the same auth-id` [6](#0-5)  exercises exactly this replay-rejection behavior (using the identical signature, but the mechanism generalizes to any signature encoding recovering the same key, since the check never inspects signature bytes).

### Impact Explanation
None. No STX/sBTC is stolen, minted, frozen, unlocked, or double-counted. `map-set signer-key-grants` is not re-triggered on replay because the tuple-based `used-signer-key-grants` check rejects the second call before that point is reached.

### Likelihood Explanation
Not applicable — the described bypass path does not exist under any precondition, since the replay guard's key is derived from `{signer-key, signer-manager, auth-id}`, none of which vary with signature encoding.

### Recommendation
No fix required for this specific concern. (General note: continuing to key `used-signer-key-grants` on the semantic tuple rather than raw signature bytes is the correct design and should be preserved in any future refactor.)

### Proof of Concept
Not applicable — no exploit exists. A confirmatory test (mirroring the existing `grant-signer-key rejects replay of the same auth-id` test) would call `grant-signer-key` once with a valid low-S signature, then again with a malleated high-S encoding of the same signature (recovering the same `signer-key`), and assert the second call returns `ERR_SIGNER_KEY_GRANT_USED`, matching the existing test's structure at [6](#0-5) .

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L174-181)
```text
(define-map used-signer-key-grants
    {
        signer-key: (buff 33),
        signer-manager: principal,
        auth-id: uint,
    }
    bool
)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2743-2811)
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

**File:** contrib/core-contract-tests/tests/pox-5/pox-5.test.ts (L947-975)
```typescript
test('grant-signer-key rejects replay of the same auth-id', () => {
  const signerSk = secp256k1.utils.randomSecretKey();
  const signerKey = secp256k1.getPublicKey(signerSk, true);
  const authId = 9001n;
  const signerSig = signSignerKeyGrant({
    signerManager: alice,
    authId,
    signerSk,
  });

  // First grant succeeds (caller === signer-manager === alice).
  txOk(
    pox5.grantSignerKey({ signerKey, signerManager: alice, authId, signerSig }),
    alice,
  );

  // Replaying the identical authorization is rejected.
  expect(
    txErr(
      pox5.grantSignerKey({
        signerKey,
        signerManager: alice,
        authId,
        signerSig,
      }),
      alice,
    ).value,
  ).toBe(pox5Errors.ERR_SIGNER_KEY_GRANT_USED);
});
```
