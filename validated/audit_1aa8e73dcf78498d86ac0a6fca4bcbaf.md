The vulnerability is real. The code comment at line 186-191 explicitly acknowledges the deadline was meant to prevent re-establishment after revocation, but the deadline only blocks replay *after* it expires — it does nothing to prevent replay *within* the deadline window. There is no nonce, no used-signature bitmap, and no check that the pusher hasn't already revoked.

---

### Title
Signature Replay in `allowPushers` Lets Creator Override Pusher Self-Revocation Within Deadline Window — (`smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol`)

### Summary
`allowPushers` accepts any valid EIP-191 signature whose deadline has not yet passed. There is no nonce or used-signature tracking. After a pusher calls `revokePusher()`, the creator can replay the pusher's original consent signature (while `block.timestamp <= deadline`) to unconditionally restore `namespaceRemapping[pusher] = creator`, nullifying the revocation without any fresh consent from the pusher.

### Finding Description
The signature committed to in `allowPushers` is:

```
keccak256(abi.encode(block.chainid, address(this), deadline, pusher, msg.sender))
``` [1](#0-0) 

The only replay guard is `_ensureDeadline(deadline)`, which checks `block.timestamp <= deadline`. [2](#0-1) 

`revokePusher()` sets `namespaceRemapping[msg.sender] = address(0)` but does not invalidate the pusher's previously issued signature. [3](#0-2) 

The code comment at lines 186–191 explicitly states the deadline was introduced to prevent exactly this re-establishment after revocation, but the deadline only closes the window after it expires — it does not prevent replay within the window. [4](#0-3) 

### Impact Explanation
After the pusher self-revokes, the creator replays the old signature. The pusher's subsequent fallback pushes — which the pusher believes are going to their own namespace — are silently redirected into the creator's namespace. Any pool consuming the creator's feed via `price(feedId, pool)` receives the pusher's data instead of the creator's intended data, constituting bad-price execution. The pusher can call `revokePusher()` again, but the creator can immediately replay again; this degenerates into a race condition that the creator (who controls transaction ordering) wins on-chain. [5](#0-4) 

### Likelihood Explanation
The creator already holds the pusher's signed consent (they called `allowPushers` originally). Replaying it costs only a single transaction. The window is bounded by the deadline, but deadlines of hours or days are typical. The pusher has no on-chain mechanism to cancel the signature before the deadline expires.

### Recommendation
Track used signatures. Add a `mapping(bytes32 => bool) private _usedConsents` and mark the signature hash as consumed on first use. Alternatively, add a per-pusher nonce to the signed payload so that `revokePusher()` can increment the nonce, invalidating all prior signatures.

### Proof of Concept
```solidity
// 1. Pusher signs consent with deadline T+1hour
uint256 deadline = block.timestamp + 1 hours;
bytes memory sig = _signConsent(PUSHER_KEY, deadline, pusher, creator);

// 2. Creator delegates pusher
vm.prank(creator);
oracle.allowPushers(deadline, _arr(pusher), _arr(sig));
assertEq(oracle.namespaceRemapping(pusher), creator);

// 3. Pusher self-revokes
vm.prank(pusher);
oracle.revokePusher();
assertEq(oracle.namespaceRemapping(pusher), address(0));

// 4. Warp to T+30min (deadline still valid), creator replays SAME signature
vm.warp(block.timestamp + 30 minutes);
vm.prank(creator);
oracle.allowPushers(deadline, _arr(pusher), _arr(sig)); // succeeds — no replay guard

// 5. Delegation is restored without fresh pusher consent
assertEq(oracle.namespaceRemapping(pusher), creator); // invariant violated

// 6. Pusher's subsequent fallback push lands in creator's namespace
vm.prank(pusher);
(bool ok,) = address(oracle).call(_wordAt(1, 0, _packRaw(9_000_000, 4, 2), uint56(block.timestamp * 1000)));
assertTrue(ok);
// creator's feed now contains pusher's data — pools reading this feed get bad prices
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

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L311-321)
```text
    fallback() override external {
        uint256 end;
        uint256 namespace;

        address creator = namespaceRemapping[msg.sender];
        if (creator == address(0)) creator = msg.sender;

        assembly ("memory-safe") {
            end := calldatasize()
            namespace := shl(96, creator) // [creator:20][zeros:12]
        }
```

**File:** smart-contracts-poc/contracts/oracles/compressed/OracleBase.sol (L124-126)
```text
    function _ensureDeadline(uint256 deadline) internal view virtual {
        require(block.timestamp <= deadline, DeadlineExceeded());
    }
```
