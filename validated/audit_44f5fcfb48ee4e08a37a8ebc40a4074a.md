Let me verify the exact validation logic in sip-031.clar to check for a coherent aliasing/identity-check vulnerability analogous to the report.Now `is-standard` confirms the semantics: it checks only that the principal's **version byte** matches the current network (mainnet/testnet), and per the Clarity docs `'SP...foo` (a contract principal) returns `true` for `is-standard` as long as the version byte matches the network — `is-standard` does **not** distinguish standard vs. contract principals, it only checks network-version match. That is exactly why the test `recipient can be set to a contract` (`${accounts.deployer.address}.blah`) passes `is-standard`, while `recipient cannot be set to a non-standard address` fails only because the *burn address* has a version byte that doesn't match either network. So `update-recipient` genuinely allows setting `recipient` to a contract principal.

### Title
Recipient permanently frozen from claiming when set to a contract principal that cannot satisfy `tx-sender == contract-caller` - (File: stackslib/src/chainstate/stacks/boot/sip-031.clar)

### Summary
`sip-031.clar`'s `validate-caller` gates both `claim` and `update-recipient` on `(is-eq (var-get recipient) contract-caller tx-sender)` — requiring the stored `recipient` to equal **both** `tx-sender` and `contract-caller` simultaneously. `update-recipient` only checks `is-standard`, which (per Clarity semantics) accepts contract principals whose version byte matches the network, not just standard principals [1](#0-0) [2](#0-1) . This mirrors the report's bug class: an equality check between a caller-derived identity and a stored recipient fails to account for a legitimate execution-context distinction (here, `tx-sender` vs `contract-caller` for contract principals), permanently blocking the intended redemption path.

### Finding Description
`tx-sender` can never equal a contract principal unless the currently executing frame is wrapped in `as-contract` from within that exact contract (i.e., the contract calling itself via `as-contract (contract-call? ...)`). A plain external call from a contract, e.g. `(contract-call? .sip-031 claim)`, sets `contract-caller` to that contract's principal but leaves `tx-sender` as the original signing account — so `contract-caller != tx-sender` and `validate-caller` fails [2](#0-1) . The only way to satisfy the triple equality when `recipient` is a contract is for that contract to implement a self-referential `as-contract (contract-call? .sip-031 claim)` pattern — exactly what the test-only `sip-031-indirect.clar` helper does, with an explicit warning that this "is not a safe way to call `claim`/`update-recipient` from an external contract, as it does not perform the necessary authorization checks" [3](#0-2) .

Since `update-recipient` accepts any principal that passes `is-standard` — including contract principals with a matching network version byte, as confirmed by the test `recipient can be set to a contract` [4](#0-3)  — a legitimate `update-recipient` call to an ordinary contract (one not specifically coded with the self-`as-contract` re-entry trick) leaves the contract permanently unable to satisfy `validate-caller`. No account — not the contract's owner, not any other principal — can subsequently call `claim` or `update-recipient` on behalf of that contract, because `tx-sender` can never equal a contract principal from an ordinary transaction or ordinary `contract-call?`.

### Impact Explanation
This permanently freezes the entire remaining SIP-031 treasury balance (up to 200M STX, including the unclaimed vesting balance and any future per-tenure mints deposited into the contract) with no recovery path, since there is no admin override, escape hatch, or alternative claim mechanism in the contract. This matches the "Critical - permanent freezing" impact category: STX intended for a valid economic purpose becomes permanently unclaimable due to a broken identity-equality check that does not account for the legitimate `tx-sender`/`contract-caller` distinction for contract principals.

### Likelihood Explanation
Likelihood is low-to-moderate: it requires the current `recipient` (initially the deployer, later any principal who has held that role) to call `update-recipient` with a contract principal that is not specially engineered with the self-`as-contract` re-entry pattern. This could happen via operational error (e.g., an org intending to route treasury funds to a multisig/DAO contract mistakenly deploys/uses a contract without the exact self-referential claim helper) or via a treasury-management upgrade path that isn't specifically designed around this quirk. Given SIP-031 governs 200M STX of protocol treasury, even a single misconfiguration has severe consequences, and the surrounding test suite already had to invent an "unsafe for production" wrapper contract to demonstrate that the (only) supported non-EOA usage pattern exists, underscoring how easy it is to set an incompatible contract as `recipient`.

### Recommendation
Add an explicit, safer indirection mechanism, for example either: (1) additionally allow `contract-caller == recipient` without requiring `tx-sender == recipient` when `recipient` is a contract principal (paired with a `trait`-based callback pattern so intent can't be reentered/spoofed), or (2) restrict `update-recipient` to true standard (non-contract) principals only, using `principal-destruct?`'s `name` field to reject any principal with a contract name, since `is-standard` alone does not encode that distinction. Additionally, add a governance-level recovery path (e.g., a delayed/admin-gated recipient reset) in case a contract is set as recipient without the required self-call capability.

### Proof of Concept
1. Deployer (current `recipient`) calls `sip-031.update-recipient(SP...XYZ.some-treasury)` where `some-treasury` is an ordinary DAO/multisig contract that does not implement a self-`as-contract` `claim` wrapper. This succeeds because `is-standard` on a contract principal with a matching network version byte returns `true` [1](#0-0) .
2. Any principal (including `some-treasury`'s own admin, calling directly or via a normal `contract-call?`) attempts `sip-031.claim()`. `contract-caller` is `some-treasury` (or the calling EOA), but `tx-sender` is never `some-treasury`'s own principal in that call, so `(is-eq (var-get recipient) contract-caller tx-sender)` fails and `claim` reverts with `ERR_NOT_ALLOWED` [5](#0-4) .
3. No party can ever construct a transaction where `tx-sender` equals `some-treasury`'s contract principal (only `some-treasury` itself could do so via a specifically coded self-`as-contract` call, which it does not implement) — confirmed by the test suite's need for a dedicated, explicitly-unsafe `sip-031-indirect.clar` helper to demonstrate the only working pattern [3](#0-2) . All remaining SIP-031 STX (vesting balance + future per-tenure mints) is now permanently frozen.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/sip-031.clar (L60-72)
```text
(define-public (update-recipient (new-recipient principal))
  (begin
    (try! (validate-caller))
    (asserts! (is-standard new-recipient) (err ERR_INVALID_RECIPIENT))
    (print {
      topic: "update-recipient",
      old-recipient: (var-get recipient),
      new-recipient: new-recipient,
    })
    (var-set recipient new-recipient)
    (ok true)
  )
)
```

**File:** stackslib/src/chainstate/stacks/boot/sip-031.clar (L76-98)
```text
(define-public (claim)
  (let ((claimable (calc-claimable-amount burn-block-height)))
    (try! (validate-caller))
    (asserts! (> claimable u0) (err ERR_NOTHING_TO_CLAIM))
    (try! (as-contract (stx-transfer? claimable tx-sender (var-get recipient))))
    (print {
      topic: "claim",
      claimable: claimable,
      recipient: (var-get recipient),
    })
    (ok claimable)
  )
)

;; Authorization check. Verify that the caller is the current `recipient`.
;; This also prevents `recipient` calling into this contract
;; via an indirect contract-call.
(define-private (validate-caller)
  (if (is-eq (var-get recipient) contract-caller tx-sender)
    (ok true)
    (err ERR_NOT_ALLOWED)
  )
)
```

**File:** contrib/core-contract-tests/contracts/sip-031-indirect.clar (L10-24)
```text
;; WARNING: This is for testing purposes only.
;; This is not a safe way to call `update-recipient` from an external contract,
;; as it does not perform the necessary authorization checks.
(define-public (update-recipient-as-contract (new-recipient principal))
  (as-contract (contract-call? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031
    update-recipient new-recipient
  ))
)

;; WARNING: This is for testing purposes only.
;; This is not a safe way to call `claim` from an external contract,
;; as it does not perform the necessary authorization checks.
(define-public (claim-as-contract)
  (as-contract (contract-call? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031 claim))
)
```

**File:** contrib/core-contract-tests/tests/sip-031/sip-031.test.ts (L443-447)
```typescript
test('recipient can be set to a contract', () => {
  const contractAddr = `${accounts.deployer.address}.blah`;
  txOk(contract.updateRecipient(contractAddr), accounts.deployer.address);
  expect(rov(contract.getRecipient())).toBe(contractAddr);
});
```
