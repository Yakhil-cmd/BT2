### Title
`allowPushers` Signature Is Not Consumed, Allowing Creator to Nullify a Pusher's Revocation Within the Deadline Window — (`smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol`)

### Summary
`CompressedOracle.allowPushers` verifies an EIP-191 pusher-consent signature but never marks it as spent. A creator who holds a valid, unexpired signature can replay it an unlimited number of times, re-establishing a delegation that the pusher has explicitly revoked via `revokePusher()`. The pusher's revocation is therefore ineffective for the entire remaining lifetime of the deadline, and the creator continues to capture the pusher's namespace writes into their own feed namespace.

### Finding Description
`allowPushers` accepts a `deadline` and a batch of `(pusher, signature)` pairs. For each pair it reconstructs the signed hash and verifies the pusher's ECDSA signature, then unconditionally writes `namespaceRemapping[pusher] = msg.sender`.

```solidity
// smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol
function allowPushers(uint256 deadline, address[] calldata pushers, bytes[] memory signatures) external {
    _ensureDeadline(deadline);
    ...
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
        keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
    );
    require(pusher == ECDSA.recover(hash, signatures[i]));
    namespaceRemapping[pusher] = msg.sender;   // ← never consumed / invalidated
    ...
}
```

The code comment acknowledges the replay risk and states the deadline is the mitigation:

> *"The deadline is likewise required: the signed consent carries no timestamp of its own, so an undated signature could re-establish a delegation AFTER the pusher revoked it."*

However, the deadline only prevents replay **after** it expires. Within the deadline window the same signature bytes can be submitted again and again. The revocation paths (`revokePusher`, `removePushers`) clear `namespaceRemapping[pusher]` but do not invalidate the original signature, so the creator can immediately call `allowPushers` again with the identical calldata to restore the mapping. [1](#0-0) 

The `revokePusher` path that the pusher relies on: [2](#0-1) 

### Impact Explanation
Every fallback push and `updateBySignature` call from the pusher's address is routed through `namespaceRemapping` to determine which namespace receives the write. While the delegation is active the pusher's oracle slot updates land in the creator's namespace, not the pusher's own namespace. A creator who replays the signature after revocation continues to receive the pusher's live feed data in their namespace. If that namespace backs a pool's `IPriceProvider`, the pool's `getBidAndAskPrice()` call consumes data the pusher intended to stop supplying, enabling bad-price execution against traders. The pusher's only practical escape is to stop pushing entirely — they cannot selectively revoke a single creator relationship within the deadline window. [3](#0-2) 

### Likelihood Explanation
The creator already possesses the signature (they used it for the initial `allowPushers` call). No additional privilege or secret is required. The only precondition is that the deadline has not yet expired, which is a normal operational window (the comment explicitly warns that undated signatures would be worse, implying deadlines are expected to be hours-to-days long). Any creator who wishes to retain a pusher's data feed against the pusher's will can do so deterministically.

### Recommendation
Maintain a per-pusher consumed-signature set (e.g., `mapping(address pusher => mapping(bytes32 sigHash => bool)) public usedDelegationSigs`) and revert if the hash has already been recorded. Alternatively, replace the deadline-based scheme with a per-pusher nonce that the pusher increments on revocation, binding each signature to a specific nonce so that revocation atomically invalidates all prior signatures.

### Proof of Concept
1. Pusher generates and signs: `keccak256(abi.encode(chainId, oracle, deadline=T+3600, pusher, creator))`.
2. Creator calls `allowPushers(T+3600, [pusher], [sig])` → `namespaceRemapping[pusher] = creator`. Pusher's slot writes now land in creator's namespace.
3. Pusher calls `revokePusher()` → `namespaceRemapping[pusher] = address(0)`. Pusher believes delegation is gone.
4. Creator immediately calls `allowPushers(T+3600, [pusher], [sig])` again with the **identical** calldata → `namespaceRemapping[pusher] = creator` is restored. No revert occurs because `_ensureDeadline` still passes and the signature is still valid.
5. Steps 3–4 can repeat indefinitely until `block.timestamp > T+3600`. During this window every push from the pusher's address continues to update the creator's namespace, and any pool whose price provider reads that namespace executes swaps against the creator-controlled feed. [4](#0-3)

### Citations

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L186-212)
```text
    /// @notice Delegates pusher wallets into the caller's namespace. The pusher's EIP-191
    ///         signature is REQUIRED — without it anyone could remap a foreign pusher
    ///         wallet into their own namespace and silently swallow its pushes. The
    ///         deadline is likewise required: the signed consent carries no timestamp of
    ///         its own, so an undated signature could re-establish a delegation AFTER the
    ///         pusher revoked it.
    function allowPushers(uint256 deadline, address[] calldata pushers, bytes[] memory signatures) external {
        _ensureDeadline(deadline);

        uint256 l = pushers.length;
        require(l == signatures.length);
        for (uint256 i; i < l; i++) {
            address pusher = pushers[i];

            if (pusher == msg.sender) {
                revert NoSelfRemapping();
            }

            bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
                keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
            );
            require(pusher == ECDSA.recover(hash, signatures[i]));

            namespaceRemapping[pusher] = msg.sender;
            emit PusherAuthorized(pusher, msg.sender);
        }
    }
```

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L236-243)
```text
    /// @notice Allows a pusher to self-revoke their delegation. After revocation the
    ///         wallet pushes into its OWN namespace again (the registrationless default).
    function revokePusher() external {
        address creator = namespaceRemapping[msg.sender];
        if (creator == address(0) || creator == msg.sender) revert NoSelfRemapping();
        namespaceRemapping[msg.sender] = address(0);
        emit PusherRevoked(msg.sender, creator);
    }
```
