### Title
Bridge `handle*Transfer` Functions Bypass `isRunning` Stop-State, Allowing KLAY Transfer and Token Mint/Transfer When Bridge Is Stopped — (File: `contracts/service_chain/bridge/BridgeTransferKLAY.sol`, `BridgeTransferERC20.sol`, `BridgeTransferERC721.sol`)

---

### Summary

The Kaia service-chain bridge exposes an `isRunning` flag that the owner sets to `false` to halt bridge operations. Every request-side entry point enforces `require(isRunning, "stopped bridge")`. The three handle-side functions — `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer` — carry no such guard. Operators can therefore continue to transfer KLAY out of the bridge and mint or transfer ERC20/ERC721 tokens to arbitrary recipients even after the owner has stopped the bridge.

---

### Finding Description

`BridgeTransferKLAY.handleKLAYTransfer` is gated only by `onlyOperators` and `nonReentrant`: [1](#0-0) 

It contains no `isRunning` check. By contrast, `_requestKLAYTransfer` — the request-side counterpart — explicitly enforces the stopped state: [2](#0-1) 

The same asymmetry exists in `BridgeTransferERC20`. `handleERC20Transfer` is gated only by `onlyOperators`: [3](#0-2) 

While `_requestERC20Transfer` checks `isRunning`: [4](#0-3) 

And in `BridgeTransferERC721`, `handleERC721Transfer` has no `isRunning` guard: [5](#0-4) 

When `modeMintBurn == true`, `handleERC20Transfer` calls `ERC20Mintable(_tokenAddress).mint(_to, _value)` and `handleERC721Transfer` calls `mintWithTokenURI`: [6](#0-5) [7](#0-6) 

`handleKLAYTransfer` always pushes native KLAY via a low-level call: [8](#0-7) 

None of these asset-moving paths is blocked by the stopped state.

The `isRunning` flag is set via `setRunningStatus` / `start`, and the test suite confirms that request functions revert when stopped, but no test verifies that handle functions are similarly blocked: [9](#0-8) 

---

### Impact Explanation

When the bridge owner calls `setRunningStatus(false)` — for example, in response to a detected exploit or a suspected operator key compromise — the intent is to halt all bridge asset movement. Because the handle functions ignore `isRunning`, operators can still:

- Drain the bridge's KLAY balance via `handleKLAYTransfer`
- Mint unbounded ERC20 tokens via `handleERC20Transfer` (mint-burn mode)
- Mint unbounded ERC721 tokens via `handleERC721Transfer` (mint-burn mode)
- Transfer ERC20/ERC721 tokens held by the bridge (lock mode)

This constitutes an unauthorized transfer and mint of bridged assets (KAIA and bridged tokens) from a contract that the owner has explicitly stopped, matching the allowed impact gate for bridge asset impact.

---

### Likelihood Explanation

Medium. Operators are trusted entities under normal conditions, mirroring the external report's "whitelisted managers" framing. However, the bridge owner may stop the bridge precisely because an operator key is suspected to be compromised. In that scenario the missing guard allows the compromised operator to continue moving assets. The trigger requires only a valid operator signature — a semi-trusted but fully reachable condition with no additional prerequisites.

---

### Recommendation

Add `require(isRunning, "stopped bridge")` to `handleKLAYTransfer`, `handleERC20Transfer`, and `handleERC721Transfer`, mirroring the guard already present in all request-side functions:

```solidity
function handleKLAYTransfer(...) public onlyOperators nonReentrant {
    require(isRunning, "stopped bridge"); // ADD THIS
    _lowerHandleNonceCheck(_requestedNonce);
    ...
}
```

If the design intent is to allow already-committed cross-chain requests to settle after a stop, introduce a separate `handleEnabled` flag that the owner can independently control, making the two-sided stop semantics explicit.

---

### Proof of Concept

1. Deploy the bridge with two operators (`op1`, `op2`) and threshold = 2.
2. Fund the bridge with 1 000 KLAY via `chargeWithoutEvent`.
3. Owner calls `setRunningStatus(false)` — bridge is now stopped.
4. Confirm: `bridge.connect(user1).fallback({value: parseEther("1.0")})` reverts with `"stopped bridge"`. ✓
5. `op1` calls `handleKLAYTransfer(txhash, from, attacker, 1000 ether, nonce, blockNum, "0x")` — succeeds.
6. `op2` calls `handleKLAYTransfer(txhash, from, attacker, 1000 ether, nonce, blockNum, "0x")` — quorum reached; `attacker` receives 1 000 KLAY.
7. Bridge KLAY balance is now 0 despite `isRunning == false`. No revert at any step.

The same sequence applies to `handleERC20Transfer` (minting ERC20 tokens) and `handleERC721Transfer` (minting ERC721 tokens) when `modeMintBurn == true`.

### Citations

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L62-74)
```text
    function handleKLAYTransfer(
        bytes32 _requestTxHash,
        address _from,
        address payable _to,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
        nonReentrant
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L98-99)
```text
        (bool ok, ) = _to.call.value(_value)("");
        require(ok, "handleKLAYTransfer: transfer failed");
```

**File:** contracts/service_chain/bridge/BridgeTransferKLAY.sol (L103-108)
```text
    function _requestKLAYTransfer(address _to, uint256 _feeLimit,  bytes memory _extraData)
        internal
        unlockedKLAY
        nonReentrant
    {
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L32-44)
```text
    function handleERC20Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _value,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L68-72)
```text
        if (modeMintBurn) {
            require(ERC20Mintable(_tokenAddress).mint(_to, _value), "handleERC20Transfer: mint failed");
        } else {
            IERC20(_tokenAddress).safeTransfer(_to, _value);
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC20.sol (L84-88)
```text
        internal
        onlyRegisteredToken(_tokenAddress)
        onlyUnlockedToken(_tokenAddress)
    {
        require(isRunning, "stopped bridge");
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L29-47)
```text
    function handleERC721Transfer(
        bytes32 _requestTxHash,
        address _from,
        address _to,
        address _tokenAddress,
        uint256 _tokenId,
        uint64 _requestedNonce,
        uint64 _requestedBlockNumber,
        string memory _tokenURI,
        bytes memory _extraData
    )
        public
        onlyOperators
    {
        _lowerHandleNonceCheck(_requestedNonce);

        if (!_voteValueTransfer(_requestedNonce)) {
            return;
        }
```

**File:** contracts/service_chain/bridge/BridgeTransferERC721.sol (L66-70)
```text
        if (modeMintBurn) {
            require(ERC721MetadataMintable(_tokenAddress).mintWithTokenURI(_to, _tokenId, _tokenURI), "mint failed");
        } else {
            IERC721(_tokenAddress).transferFrom(address(this), _to, _tokenId);
        }
```

**File:** contracts/test/Bridge/bridge.test.ts (L851-858)
```typescript
    it("stopped bridge", async function() {
      const fixture = await loadFixture(deployBridgeConfiguredFixture);
      const { bridge, owner, user1 } = fixture;

      await bridge.connect(owner).start(false);
      expect(bridge.connect(user1).fallback({value: parseEther("1.0")}))
        .to.be.revertedWith("stopped bridge");
    });
```
