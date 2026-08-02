No vulnerability found for this question.

**Reasoning:**

`vector::index_of` performs a straightforward linear scan using exact equality comparison (`self.borrow(i) == e`) and returns the index of the first exact match, or `(false, 0)` if no match exists [1](#0-0) . There is no mechanism by which a "duplicated or crafted address" could cause it to bind to the wrong owner's index — Move's `address` type equality is an exact byte-for-byte comparison with no aliasing, collision, or truncation behavior possible.

Within `multisig_account.move`, owner lists are explicitly deduplicated by `validate_owners`, which scans the owners vector and asserts `!found` via `index_of` before allowing an address to be added, rejecting any duplicate owner entry with `EDUPLICATE_OWNER` [2](#0-1) . Approval/rejection tallying (`num_approvals_and_rejections_internal`) iterates the (deduplicated) owners vector and looks up each owner's vote in a `simple_map`, not via `index_of` matching against `secondary_signers`, so there is no path where a crafted address list can misattribute an approval to an unintended owner [3](#0-2) .

Additionally, `multisig_account.move` is an on-chain Move module invoked via normal entry-function execution — it is not part of the transaction admission stack (mempool, vm-validator, authenticator/prologue signer binding) that this review's scope targets. The `secondary_signers` concept relevant to admission lives in `transaction_context.move`/`transaction_validation.move`, which bind secondary signer addresses directly from the authenticated transaction structure rather than through any `vector::index_of` owner-matching logic [4](#0-3) .

Since `index_of`'s equality semantics are exact and owner lists are deduplicated before any approval-set check, there is no way for unprivileged input to cause `index_of` to bind approval to the wrong owner index, and thus no admission-boundary exploit exists here.

### Citations

**File:** aptos-move/framework/move-stdlib/sources/vector.move (L233-244)
```text
    public fun index_of<Element>(self: &vector<Element>, e: &Element): (bool, u64) {
        let i = 0;
        let len = self.length();
        while (i < len) {
            if (self.borrow(i) == e) return (true, i);
            i += 1;
        };
        (false, 0)
    }
    spec index_of {
        pragma intrinsic = true;
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1510-1518)
```text
    fun validate_owners(owners: &vector<address>, multisig_account: address) {
        let distinct_owners: vector<address> = vector[];
        owners.for_each_ref(|owner| {
            assert!(owner != &multisig_account, error::invalid_argument(EOWNER_CANNOT_BE_MULTISIG_ACCOUNT_ITSELF));
            let (found, _) = distinct_owners.index_of(owner);
            assert!(!found, error::invalid_argument(EDUPLICATE_OWNER));
            distinct_owners.push_back(*owner);
        });
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1532-1548)
```text
    inline fun num_approvals_and_rejections_internal(owners: &vector<address>, transaction: &MultisigTransaction): (u64, u64) {
        let num_approvals = 0;
        let num_rejections = 0;

        let votes = &transaction.votes;
        owners.for_each_ref(|owner| {
            if (simple_map::contains_key(votes, owner)) {
                if (*simple_map::borrow(votes, owner)) {
                    num_approvals += 1;
                } else {
                    num_rejections += 1;
                };
            }
        });

        (num_approvals, num_rejections)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L1-1)
```text
module aptos_framework::transaction_validation {
```
