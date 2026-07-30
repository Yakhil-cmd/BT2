[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/crypto/zklogin_verified_issuer.move (L17-24)
```text
public struct VerifiedIssuer has key {
    /// The ID of this VerifiedIssuer
    id: UID,
    /// The address this VerifiedID is associated with
    owner: address,
    /// The issuer
    issuer: String,
}
```

**File:** crates/sui-framework/packages/sui-framework/sources/crypto/zklogin_verified_issuer.move (L36-57)
```text
/// Delete a VerifiedIssuer
public fun delete(verified_issuer: VerifiedIssuer) {
    let VerifiedIssuer { id, owner: _, issuer: _ } = verified_issuer;
    id.delete();
}

/// Verify that the caller's address was created using zklogin with the given issuer. If so, a VerifiedIssuer object
/// with the issuers id transferred to the caller.
///
/// Aborts with `EInvalidProof` if the verification fails.
public fun verify_zklogin_issuer(address_seed: u256, issuer: String, ctx: &mut TxContext) {
    let sender = ctx.sender();
    assert!(check_zklogin_issuer(sender, address_seed, &issuer), EInvalidProof);
    transfer::transfer(
        VerifiedIssuer {
            id: object::new(ctx),
            owner: sender,
            issuer,
        },
        sender,
    )
}
```
