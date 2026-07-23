### Title
Pusher Delegation Signature Replay Overrides `revokePusher()` Within Deadline Window — (File: `smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol`)

---

### Summary

`allowPushers` accepts a pusher's EIP-191 consent signature that commits to `(chainid, oracle, deadline, pusher, creator)` but contains **no nonce**. After a pusher calls `revokePusher()` to clear their delegation, the creator can replay the original signature — unchanged — to immediately re-establish `namespaceRemapping[pusher] = creator`. The pusher's self-revocation is therefore not a reliable mechanism; it can be overridden an unlimited number of times until the deadline expires.

---

### Finding Description

The signed consent message in `allowPushers` is:

```solidity
bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
    keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
);
require(pusher == ECDSA.recover(hash, signatures[i]));
namespaceRemapping[pusher] = msg.sender;
``` [1](#0-0) 

The NatSpec comment on the function explicitly acknowledges the replay risk and claims the deadline mitigates it:

> *"The deadline is likewise required: the signed consent carries no timestamp of its own, so an undated signature could re-establish a delegation AFTER the pusher revoked it."* [2](#0-1) 

The comment is incorrect. The deadline bounds the outer window but does **not** prevent replay within that window. `revokePusher` clears `namespaceRemapping[msg.sender]` to `address(0)`:

```solidity
function revokePusher() external {
    address creator = namespaceRemapping[msg.sender];
    if (creator == address(0) || creator == msg.sender) revert NoSelfRemapping();
    namespaceRemapping[msg.sender] = address(0);
    emit PusherRevoked(msg.sender, creator);
}
``` [3](#0-2) 

But because the signature carries no nonce, the creator can immediately call `allowPushers` again with the identical `(deadline, pusher, sig)` tuple, writing `namespaceRemapping[pusher] = creator` again. No new signature from the pusher is required. There is no on-chain state that distinguishes a "fresh" consent from a replayed one.

**Attack sequence:**

1. Pusher signs consent for creator with `deadline = T`.
2. Creator calls `allowPushers(T, [pusher], [sig])` → `namespaceRemapping[pusher] = creator`.
3. Pusher's key is compromised; pusher calls `revokePusher()` → `namespaceRemapping[pusher] = address(0)`.
4. Creator (or an automated keeper holding the original sig) calls `allowPushers(T, [pusher], [sig])` again → `namespaceRemapping[pusher] = creator`. Revocation overridden.
5. Steps 3–4 repeat indefinitely until `block.timestamp > T`.

The no-nonce invariant is confirmed by the absence of any `pusherNonce` or equivalent counter anywhere in the oracle contracts.

---

### Impact Explanation

The `fallback` push path resolves the namespace from `namespaceRemapping[msg.sender]`:

```solidity
address creator = namespaceRemapping[msg.sender];
if (creator == address(0)) creator = msg.sender;
``` [4](#0-3) 

While the delegation is re-established, every push from the compromised pusher key lands in the creator's namespace, overwriting the creator's live oracle slots with attacker-controlled bid/ask data. If the creator's namespace feeds a `PriceProvider` consumed by a Metric OMM pool, the corrupted quotes reach `getBidAndAskPrice()` inside `swap`, enabling bad-price execution: traders receive more output than the oracle permits, or the pool receives less input than owed, directly draining LP principal.

The pusher's only recourse — `revokePusher()` — is rendered ineffective for the entire remaining deadline window, which can be arbitrarily long (the function imposes no cap on `deadline`).

---

### Likelihood Explanation

Medium. The creator must retain the original signature (standard operational practice for keeper bots). Any automated system that re-establishes delegations on revocation events triggers this without deliberate malice. A compromised pusher key combined with a long deadline and an active keeper is a realistic production scenario.

---

### Recommendation

Add a per-pusher revocation nonce to the signed message and increment it on every `revokePusher` / `removePushers` call:

```solidity
mapping(address => uint256) public pusherRevocationNonce;

// allowPushers — include nonce in hash:
bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
    keccak256(abi.encode(
        block.chainid, address(this), deadline,
        pusher, msg.sender,
        pusherRevocationNonce[pusher]   // <-- add this
    ))
);

// revokePusher — invalidate all prior signatures:
namespaceRemapping[msg.sender] = address(0);
pusherRevocationNonce[msg.sender]++;   // <-- add this

// removePushers — same:
namespaceRemapping[pusher] = address(0);
pusherRevocationNonce[pusher]++;       // <-- add this
```

This ensures that once a pusher revokes, every previously signed consent is immediately invalidated on-chain, regardless of its deadline.

---

### Proof of Concept

```solidity
// Setup: pusher signs consent for creator, deadline = now + 7 days
uint256 deadline = block.timestamp + 7 days;
bytes32 digest = keccak256(abi.encode(chainId, oracle, deadline, pusher, creator));
bytes memory sig = sign(pusherKey, digest);

// Step 1: creator establishes delegation
vm.prank(creator);
oracle.allowPushers(deadline, toArray(pusher), toArray(sig));
assertEq(oracle.namespaceRemapping(pusher), creator); // delegated

// Step 2: pusher's key is compromised; pusher revokes
vm.prank(pusher);
oracle.revokePusher();
assertEq(oracle.namespaceRemapping(pusher), address(0)); // revoked

// Step 3: creator replays the IDENTICAL signature — no new pusher consent needed
vm.prank(creator);
oracle.allowPushers(deadline, toArray(pusher), toArray(sig));
assertEq(oracle.namespaceRemapping(pusher), creator); // ← revocation overridden

// Step 4: attacker (holding pusher key) pushes manipulated prices into creator's namespace
// → corrupted oracle data reaches any pool using creator's PriceProvider
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

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L204-209)
```text
            bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
                keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
            );
            require(pusher == ECDSA.recover(hash, signatures[i]));

            namespaceRemapping[pusher] = msg.sender;
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

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L315-316)
```text
        address creator = namespaceRemapping[msg.sender];
        if (creator == address(0)) creator = msg.sender;
```
