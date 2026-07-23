### Title
Consent Signature Replay in `allowPushers` Defeats `revokePusher` — (`smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol`)

---

### Summary

`allowPushers` verifies a pusher's EIP-191 consent signature but never marks it as consumed. Because the only replay guard is a deadline check, a creator can re-submit the same signature any number of times before the deadline expires. This lets the creator silently re-establish a delegation that the pusher already revoked via `revokePusher()`, permanently redirecting the pusher's fallback writes into the creator's namespace against the pusher's will.

---

### Finding Description

`allowPushers` builds and verifies a consent hash over `(chainid, address(this), deadline, pusher, msg.sender)` and then writes `namespaceRemapping[pusher] = msg.sender`. [1](#0-0) 

The only replay guard is `_ensureDeadline(deadline)`, which rejects calls after the deadline but accepts any number of calls before it. [2](#0-1) 

`revokePusher` clears the mapping to `address(0)`: [3](#0-2) 

There is no per-signature invalidation record, no per-pusher nonce, and no check in `allowPushers` that the pusher has not already revoked. The code's own comment acknowledges the replay risk ("an undated signature could re-establish a delegation AFTER the pusher revoked it") and claims the deadline solves it — but the deadline only prevents replay *after* it expires, not *before*. [4](#0-3) 

The `fallback` push path resolves the namespace from `namespaceRemapping[msg.sender]` at call time: [5](#0-4) 

So every push the pusher makes after revocation — including pushes intended for their own namespace — is silently redirected to the creator's namespace as long as the creator keeps replaying the original signature.

---

### Impact Explanation

The `CompressedOracle` is the open price-data layer consumed by price providers, which in turn drive bid/ask quotes for `MetricOmmPool.swap`. If the creator's namespace is corrupted with data the pusher no longer intends to provide (e.g., the pusher has switched to a different asset or stopped operating), the price provider reads a wrong or stale mid/spread pair and passes it to the pool. This constitutes bad-price execution: traders receive fills at prices that do not reflect the oracle's intended state, causing direct loss of principal to one side of every affected swap.

---

### Likelihood Explanation

The attacker is the creator — a normal, non-privileged participant who obtained a valid consent signature from the pusher. The replay requires only re-calling `allowPushers` with the already-public signature and the same deadline, which is a zero-cost on-chain transaction. The window is the full duration of the original deadline (creators are incentivized to request long deadlines). No special access, no front-running, and no off-chain coordination is needed beyond possessing the original signature bytes.

---

### Recommendation

Track consumed signatures. Add a `mapping(bytes32 => bool) private _usedConsentHashes` and after verifying each signature, require `!_usedConsentHashes[hash]` then set it to `true`. This makes every consent signature single-use regardless of deadline, so `revokePusher` permanently ends the delegation for that signed consent. Alternatively, introduce a per-pusher nonce (`mapping(address => uint256) public pusherNonce`) that the pusher increments on revocation, and include it in the signed payload so any previously issued signature becomes invalid after revocation.

---

### Proof of Concept

```solidity
// 1. Pusher signs consent for creator, deadline = now + 365 days
bytes memory sig = _signConsent(PUSHER_KEY, deadline, pusher, creator);

// 2. Creator establishes delegation
vm.prank(creator);
oracle.allowPushers(deadline, _arr(pusher), _arr(sig));
assertEq(oracle.namespaceRemapping(pusher), creator); // delegated

// 3. Pusher revokes — intends to push into own namespace from now on
vm.prank(pusher);
oracle.revokePusher();
assertEq(oracle.namespaceRemapping(pusher), address(0)); // cleared

// 4. Creator replays the SAME signature before the deadline
vm.prank(creator);
oracle.allowPushers(deadline, _arr(pusher), _arr(sig)); // succeeds — no replay guard
assertEq(oracle.namespaceRemapping(pusher), creator);   // delegation re-established

// 5. Pusher's subsequent fallback push lands in creator's namespace, not their own
vm.prank(pusher);
(bool ok,) = address(oracle).call(wordBytes); // redirected to creator namespace
// creator's feed now contains data the pusher did not intend to provide
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

**File:** smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol (L192-211)
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
