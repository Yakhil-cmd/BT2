### Title
EIP-191 Pusher-Delegation Signature Can Be Replayed Within Its Deadline Window to Nullify Revocation — (`File: smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol`)

### Summary

`CompressedOracle.allowPushers` verifies a one-time EIP-191 consent signature from a pusher but never marks that signature as consumed. After a pusher calls `revokePusher()` to clear their delegation, the creator can immediately replay the original signature (provided the deadline has not yet expired) to re-establish the delegation. This cycle can repeat indefinitely within the deadline window, making revocation effectively impossible until the deadline passes.

### Finding Description

`allowPushers` constructs a hash over `(chainid, address(this), deadline, pusher, msg.sender)` and verifies the pusher's ECDSA signature: [1](#0-0) 

The only replay guard is `_ensureDeadline(deadline)`, which rejects calls after the deadline but permits unlimited re-submissions of the same `(deadline, pusher, creator)` tuple before it. There is no used-signature bitmap, nonce, or per-pusher invalidation flag.

`revokePusher` clears `namespaceRemapping[msg.sender]` to `address(0)`: [2](#0-1) 

Because `allowPushers` does not record that the signature was already consumed, the creator can call `allowPushers` again with the identical `(deadline, pusher[], signatures[])` arguments immediately after the pusher revokes, restoring `namespaceRemapping[pusher] = creator`.

The code comment at line 186–191 explicitly acknowledges the replay concern and states the deadline is the chosen mitigation, but the deadline only closes the window after expiry — it does not prevent intra-window replay: [3](#0-2) 

### Impact Explanation

`namespaceRemapping` determines where every `fallback()` push from a delegated pusher lands. While the pusher is re-delegated against their will, all their slot writes are attributed to the creator's namespace instead of their own: [4](#0-3) 

Consequences:
1. **Broken revocation invariant**: a pusher who explicitly revokes remains effectively delegated for the full deadline window (up to the maximum deadline enforced by `_ensureDeadline`).
2. **Oracle data misattribution**: the pusher's price data continues to overwrite the creator's namespace feeds, which are consumed by `price()` and downstream pool price providers.
3. **Pusher's own namespace starved**: because pushes are redirected, the pusher cannot write to their own namespace during the window, breaking any pool or provider that reads from the pusher's own feed.

If the pusher is trying to stop providing data for a pool (e.g., because the data is stale or the relationship ended), the creator can prevent this for the entire deadline window, potentially sustaining bad-price execution in any pool backed by that namespace.

### Likelihood Explanation

The trigger requires only that the creator retain the original `(deadline, pushers[], signatures[])` calldata — trivially available from the original on-chain transaction — and call `allowPushers` again after the pusher revokes. No privileged access, no special tokens, and no complex setup are needed. The window is bounded by the deadline, but typical delegation deadlines are hours to days.

### Recommendation

Record each consumed `(pusher, creator, deadline)` tuple and reject re-use:

```solidity
mapping(bytes32 => bool) private _usedDelegationSig;

// inside allowPushers loop, after signature recovery:
bytes32 sigKey = keccak256(abi.encode(pusher, msg.sender, deadline));
if (_usedDelegationSig[sigKey]) revert SignatureAlreadyUsed();
_usedDelegationSig[sigKey] = true;
```

Alternatively, introduce a per-pusher nonce that must be included in the signed message and incremented on each successful delegation, making every consent signature single-use by construction.

### Proof of Concept

```
1. Pusher signs consent: hash = keccak256(abi.encode(chainid, oracle, deadline=T+24h, pusher, creator))
2. Creator calls allowPushers(T+24h, [pusher], [sig]) at time T
   → namespaceRemapping[pusher] = creator  ✓
3. Pusher calls revokePusher() at time T+1h
   → namespaceRemapping[pusher] = address(0)  ✓ (pusher believes they are free)
4. Creator calls allowPushers(T+24h, [pusher], [sig]) again at time T+2h
   → _ensureDeadline passes (T+2h < T+24h)
   → same signature recovers to pusher  ✓
   → namespaceRemapping[pusher] = creator  (revocation nullified)
5. Pusher's fallback() pushes now land in creator's namespace again.
6. Steps 3–5 repeat until T+24h; pusher cannot escape the delegation.
``` [5](#0-4)

### Citations

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L186-191)
```text
    /// @notice Delegates pusher wallets into the caller's namespace. The pusher's EIP-191
    ///         signature is REQUIRED — without it anyone could remap a foreign pusher
    ///         wallet into their own namespace and silently swallow its pushes. The
    ///         deadline is likewise required: the signed consent carries no timestamp of
    ///         its own, so an undated signature could re-establish a delegation AFTER the
    ///         pusher revoked it.
```

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L192-212)
```text
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

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L238-243)
```text
    function revokePusher() external {
        address creator = namespaceRemapping[msg.sender];
        if (creator == address(0) || creator == msg.sender) revert NoSelfRemapping();
        namespaceRemapping[msg.sender] = address(0);
        emit PusherRevoked(msg.sender, creator);
    }
```

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L314-317)
```text

        address creator = namespaceRemapping[msg.sender];
        if (creator == address(0)) creator = msg.sender;

```
