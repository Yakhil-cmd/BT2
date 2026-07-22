### Title
Pusher consent signature has no nonce, making `revokePusher()` bypassable via replay — (`smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol`)

### Summary

`CompressedOracle.allowPushers` verifies a pusher's EIP-191 consent signature that commits to `(chainid, oracle, deadline, pusher, creator)` but includes **no nonce**. The only replay guard is the `deadline`. After a pusher calls `revokePusher()` to clear their delegation, the creator can immediately call `allowPushers` again with the **identical signature** (deadline still in the future) to silently re-establish the mapping. The contract's own NatSpec acknowledges the deadline is the sole anti-replay mechanism, yet a deadline alone cannot prevent intra-window replay.

### Finding Description

The signed consent message is constructed at lines 204–205:

```solidity
bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
    keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
);
``` [1](#0-0) 

There is no per-pusher nonce, no used-signature bitmap, and no state that changes on the pusher side when `revokePusher()` fires. `revokePusher()` only zeroes `namespaceRemapping[msg.sender]`:

```solidity
namespaceRemapping[msg.sender] = address(0);
``` [2](#0-1) 

Because the signed tuple is identical to the one used in the original `allowPushers` call, and the deadline has not expired, the creator can call `allowPushers` a second time with the same `(deadline, [pusher], [sig])` arguments. The `_ensureDeadline` check passes, ECDSA recovery succeeds, and `namespaceRemapping[pusher]` is written back to `creator`.

The NatSpec comment at lines 186–191 explicitly states the deadline is the mechanism preventing post-revocation replay, confirming the developers were aware of the attack class but chose an incomplete mitigation: [3](#0-2) 

**Exploit path:**

1. Pusher signs consent: `sig = sign(chainid ‖ oracle ‖ deadline+365d ‖ pusher ‖ creator)`.
2. Creator calls `allowPushers(deadline, [pusher], [sig])` → `namespaceRemapping[pusher] = creator`.
3. Pusher's key is compromised; attacker begins pushing manipulated prices into the creator's namespace.
4. Pusher calls `revokePusher()` → `namespaceRemapping[pusher] = address(0)`.
5. Creator (or an automated keeper holding the original sig) calls `allowPushers` again with the **same** `(deadline, [pusher], [sig])` — deadline still valid, signature still valid.
6. `namespaceRemapping[pusher] = creator` is restored; the compromised pusher's bad prices continue to land in the creator's namespace.
7. Any pool whose `PriceProvider` reads from this `CompressedOracle` feed now receives manipulated bid/ask prices → swap conservation failure or bad-price execution.

### Impact Explanation

A pool whose price provider is backed by a `CompressedOracle` feed will execute swaps at the attacker-controlled price. Traders receive more output than the oracle permits (swap conservation failure) or the pool is drained via repeated one-sided swaps at the manipulated price. This is a direct loss of LP principal and protocol fees, matching the "bad-price execution" and "pool insolvency" impact categories.

### Likelihood Explanation

The preconditions are:
- A pusher signs a consent with a non-trivial deadline (standard operational practice for long-lived delegations).
- The creator retains the original signature (trivially true — it was submitted on-chain and is in calldata history).
- The pusher's key is compromised or the pusher legitimately wants to stop.

The creator replaying the consent can be accidental (automated keeper re-submitting cached delegation transactions) or deliberate. No privileged factory or protocol-owner key is required; only the pool-admin-equivalent creator role, which is semi-trusted per the contest scope.

### Recommendation

Add a per-pusher nonce to the signed message and increment it on every successful revocation:

```solidity
mapping(address => uint256) public pusherNonce;

// In allowPushers:
keccak256(abi.encode(block.chainid, address(this), deadline,
                     pusher, msg.sender, pusherNonce[pusher]))

// In revokePusher / removePushers:
pusherNonce[msg.sender]++;   // or pusherNonce[pusher]++
namespaceRemapping[...] = address(0);
```

This is the exact pattern recommended in the eBTC report (`increaseNonce`) and ensures that any signature issued before a revocation is permanently invalidated, regardless of its deadline.

### Proof of Concept

```solidity
// 1. Pusher signs consent with 1-year deadline
uint256 deadline = block.timestamp + 365 days;
bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
    keccak256(abi.encode(block.chainid, address(oracle), deadline, pusher, creator))
);
(uint8 v, bytes32 r, bytes32 s) = vm.sign(PUSHER_KEY, hash);
bytes memory sig = abi.encodePacked(r, s, v);

// 2. Creator establishes delegation
vm.prank(creator);
oracle.allowPushers(deadline, _arr(pusher), _arr(sig));
assertEq(oracle.namespaceRemapping(pusher), creator);

// 3. Pusher revokes
vm.prank(pusher);
oracle.revokePusher();
assertEq(oracle.namespaceRemapping(pusher), address(0));

// 4. Creator replays the SAME signature — succeeds, revocation undone
vm.prank(creator);
oracle.allowPushers(deadline, _arr(pusher), _arr(sig));
assertEq(oracle.namespaceRemapping(pusher), creator); // ← revocation bypassed

// 5. Compromised pusher key pushes manipulated price into creator namespace
// → pool swap executes at attacker-controlled price
```

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

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L204-207)
```text
            bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
                keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
            );
            require(pusher == ECDSA.recover(hash, signatures[i]));
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
