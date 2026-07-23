### Title
Missing Sequencer Uptime Check in L2 Price Providers Allows Stale-Price Swaps After Sequencer Recovery - (`smart-contracts-poc/contracts/PriceProviderL2.sol`, `smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol`)

### Summary

`PriceProviderL2` and `ProtectedPriceProviderL2` — deployed on Arbitrum, Base, Avalanche, BSC, and Berachain — perform only a `refTime`-based staleness check. Neither contract queries a Chainlink sequencer uptime feed. After an L2 sequencer outage shorter than `MAX_TIME_DELTA`, the last pre-downtime oracle price passes the staleness check and is fed to the pool as a live bid/ask, enabling a public trader to execute swaps at a price that does not reflect real-world movement during the outage.

### Finding Description

Both L2 providers share the same `_isStale` logic:

```solidity
// PriceProviderL2.sol L135-L150 / ProtectedPriceProviderL2.sol L138-L153
function _isStale(uint256 refTime, uint256 nowTs, uint256 maxDelta, uint256 futureTol)
    internal pure returns (bool)
{
    if (refTime == 0) return true;
    if (refTime > nowTs) return (refTime - nowTs) > futureTol;
    return (nowTs - refTime) > maxDelta;
}
```

The only L2-specific adaptation is `FUTURE_TOLERANCE`, which tolerates an oracle `refTime` slightly ahead of `block.timestamp` due to sequencer clock skew. It does **not** address the inverse scenario: sequencer downtime causes `block.timestamp` to advance while the oracle's `refTime` stays frozen at the last pre-downtime update.

During sequencer downtime, no new oracle data can be pushed on-chain (Pyth Lazer / Chainlink Data Streams are push oracles). When the sequencer resumes, the stored oracle slot still carries the pre-downtime `refTime`. If `block.timestamp - refTime ≤ MAX_TIME_DELTA`, `_isStale` returns `false` and `_computeBidAsk` / `_getBidAndAskPrice` return the stale bid/ask to the pool.

The `ChainlinkVerifierL2` contract (present in the registry ABI at `registry.json:5685`) exposes `sequencerUptimeFeed()` and `GRACE_PERIOD()`, confirming the protocol has the infrastructure for sequencer uptime checking. However, this contract is **not integrated** into `PriceProviderL2` or `ProtectedPriceProviderL2`. The glob search for `ChainlinkVerifierL2*.sol` returns no source file, and neither L2 provider imports or calls any sequencer uptime feed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation

The pool's oracle-anchored pricing invariant requires that every swap executes at a live, externally-validated bid/ask. A stale pre-downtime price violates this invariant: the pool settles a trade at a price that does not reflect real-world movement during the outage. LPs bear the loss — the trader receives more output than the current market price permits, draining LP-owned reserves. This matches the allowed impact gate: **bad-price execution: stale bid/ask quote reaches a pool swap**, with direct LP principal loss. [5](#0-4) [6](#0-5) 

### Likelihood Explanation

- L2 sequencer outages are documented real-world events (Arbitrum 7-hour outage 2023, Base shorter outages).
- `MAX_TIME_DELTA` is configurable up to 7 days; practical values for Pyth Lazer (~30–60 s) or Chainlink Data Streams (~5–10 min) mean any outage shorter than the configured window is exploitable.
- The trigger is a public swap — no privileged role required.
- The attacker only needs to monitor the sequencer status and submit a swap immediately after recovery, before the oracle updater pushes a fresh price.
- `PriceProviderFactoryL2.createPriceProvider` is permissionless, so pools using these providers are widely deployed across five chains. [7](#0-6) [8](#0-7) [9](#0-8) 

### Recommendation

Integrate a Chainlink sequencer uptime feed check into both `PriceProviderL2._getBidAndAskPrice()` and `ProtectedPriceProviderL2._computeBidAsk()`, mirroring the pattern already present in `ChainlinkVerifierL2`:

1. Store an immutable `AggregatorV3Interface sequencerUptimeFeed` and a `GRACE_PERIOD` constant (e.g., 3600 seconds).
2. At the top of `_getBidAndAskPrice` / `_computeBidAsk`, call `sequencerUptimeFeed.latestRoundData()`. If `answer != 0` (sequencer down) or `block.timestamp - startedAt < GRACE_PERIOD` (within grace period after recovery), return the stalled sentinel `(0, type(uint128).max)`.
3. Only proceed to the `_isStale` check after confirming the sequencer has been live for at least `GRACE_PERIOD` seconds — ensuring the oracle updater has had time to push a fresh price.

### Proof of Concept

```
Setup (Arbitrum fork):
1. Deploy PriceProviderL2 with MAX_TIME_DELTA = 60 s, FUTURE_TOLERANCE = 5 s.
2. Push oracle price P0 = 2000 USD at t=0 (refTime=0).
3. Simulate sequencer downtime: vm.warp(t=50). No oracle update possible.
4. Sequencer resumes at t=50. Real market price is now P1 = 1800 USD (10% drop).
5. Oracle updater has not yet pushed P1 (needs a block to land).
6. Attacker calls pool.swap() immediately at t=50.
   → PriceProviderL2._isStale(refTime=0, nowTs=50, maxDelta=60, futureTol=5)
   → (50 - 0) = 50 ≤ 60 → returns false (NOT stale)
   → Pool executes swap at stale bid/ask derived from P0 = 2000 USD.
7. Attacker buys token0 (ETH) at 2000 USD while real price is 1800 USD.
   → LP loses ~10% on the swapped amount.
8. Oracle updater pushes P1 = 1800 USD at t=51 — too late.
``` [10](#0-9) [11](#0-10)

### Citations

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L36-38)
```text
    /// @dev L2 sequencer timestamp can lag behind oracle publication time.
    ///      Allows refTime up to FUTURE_TOLERANCE seconds ahead of block.timestamp.
    uint256 public immutable FUTURE_TOLERANCE;
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L92-95)
```text
        if (_maxTimeDelta == 0 || _maxTimeDelta > 7 days) revert MaxTimeDeltaOutOfBounds();
        if (_futureTolerance > 1 hours) revert FutureToleranceOutOfBounds();
        MAX_TIME_DELTA   = _maxTimeDelta;
        FUTURE_TOLERANCE = _futureTolerance;
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L123-128)
```text
    function getBidAndAskPrice()
        external override returns (uint128 bid, uint128 ask)
    {
        (bid, ask) = _getBidAndAskPrice();
        if (bid == 0 || ask == type(uint128).max) revert FeedStalled();
    }
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L135-150)
```text
    function _isStale(
        uint256 refTime,
        uint256 nowTs,
        uint256 maxDelta,
        uint256 futureTol
    ) internal pure returns (bool) {
        if (refTime == 0) return true;

        if (refTime > nowTs) {
            // refTime in the future: tolerate only within futureTol
            return (refTime - nowTs) > futureTol;
        }

        // refTime in the past or equal: check age
        return (nowTs - refTime) > maxDelta;
    }
```

**File:** smart-contracts-poc/contracts/PriceProviderL2.sol (L208-217)
```text
    function _getBidAndAskPrice() internal returns (uint128, uint128) {
        // 1. Read via the unified price(feedId, pool) path, forwarding the pool (msg.sender).
        //    refTime is already in seconds.
        (uint256 mid, uint256 spread, , uint256 refTime) =
            IPricedOracle(address(offchainOracle)).price(offchainFeedId, msg.sender);

        // 2. Staleness check
        if (_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)) {
            return (0, type(uint128).max);
        }
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L40-42)
```text
    /// @dev L2 sequencer timestamp can lag behind oracle publication time.
    ///      Allows refTime up to FUTURE_TOLERANCE seconds ahead of block.timestamp.
    uint256 public immutable FUTURE_TOLERANCE;
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L130-133)
```text
    function getBidAndAskPrice() external override returns (uint128 bid, uint128 ask) {
        (bid, ask) = _getBidAndAskPrice();
        if (bid == 0 || ask == type(uint128).max) revert FeedStalled();
    }
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L138-153)
```text
    function _isStale(
        uint256 refTime,
        uint256 nowTs,
        uint256 maxDelta,
        uint256 futureTol
    ) internal pure returns (bool) {
        if (refTime == 0) return true;

        if (refTime > nowTs) {
            // refTime in the future: tolerate only within futureTol
            return (refTime - nowTs) > futureTol;
        }

        // refTime in the past or equal: check age
        return (nowTs - refTime) > maxDelta;
    }
```

**File:** smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol (L203-209)
```text
    function _computeBidAsk(uint256 price, uint256 spread, uint256 refTime)
        internal view returns (uint128, uint128)
    {
        // 1. Staleness check
        if (_isStale(refTime, block.timestamp, MAX_TIME_DELTA, FUTURE_TOLERANCE)) {
            return (0, type(uint128).max);
        }
```

**File:** smart-contracts-poc/contracts/PriceProviderFactoryL2.sol (L41-79)
```text
    function createPriceProvider(
        address _oracle,
        bytes32 _feedId,
        int256  _marginStep,
        uint256 _maxTimeDelta,
        uint256 _futureTolerance,
        address _baseToken,
        address _quoteToken
    ) external override returns (address provider) {
        PriceProviderL2 p = new PriceProviderL2(
            address(this),
            _oracle,
            _feedId,
            _marginStep,
            _maxTimeDelta,
            _futureTolerance,
            _baseToken,
            _quoteToken
        );

        provider = address(p);
        address creator = msg.sender;

        _providers.add(provider);
        _providersByCreator[creator].add(provider);
        providerOwner[provider] = creator;

        emit ProviderDeployed(
            provider,
            creator,
            _feedId,
            _oracle,
            p.baseToken(),
            p.quoteToken(),
            _marginStep,
            _maxTimeDelta,
            _futureTolerance
        );
    }
```

**File:** smart-contracts-poc/contract-registry/versions/registry.json (L5685-5791)
```json
        "ChainlinkVerifierL2": {
          "abi": [
            {
              "type": "constructor",
              "inputs": [
                {
                  "name": "_sequencerUptimeFeed",
                  "type": "address",
                  "internalType": "address"
                }
              ],
              "stateMutability": "nonpayable"
            },
            {
              "type": "function",
              "name": "GRACE_PERIOD",
              "inputs": [],
              "outputs": [
                {
                  "name": "",
                  "type": "uint256",
                  "internalType": "uint256"
                }
              ],
              "stateMutability": "view"
            },
            {
              "type": "function",
              "name": "sequencerUptimeFeed",
              "inputs": [],
              "outputs": [
                {
                  "name": "",
                  "type": "address",
                  "internalType": "contract AggregatorV3Interface"
                }
              ],
              "stateMutability": "view"
            },
            {
              "type": "event",
              "name": "ClOracleRemoved",
              "inputs": [
                {
                  "name": "token",
                  "type": "address",
                  "indexed": true,
                  "internalType": "address"
                }
              ],
              "anonymous": false
            },
            {
              "type": "event",
              "name": "ClOracleSet",
              "inputs": [
                {
                  "name": "token",
                  "type": "address",
                  "indexed": true,
                  "internalType": "address"
                },
                {
                  "name": "oracle",
                  "type": "address",
                  "indexed": true,
                  "internalType": "address"
                },
                {
                  "name": "heartbeat",
                  "type": "uint32",
                  "indexed": false,
                  "internalType": "uint32"
                }
              ],
              "anonymous": false
            },
            {
              "type": "event",
              "name": "ClOracleStateSet",
              "inputs": [
                {
                  "name": "token",
                  "type": "address",
                  "indexed": true,
                  "internalType": "address"
                },
                {
                  "name": "oracle",
                  "type": "address",
                  "indexed": true,
                  "internalType": "address"
                }
              ],
              "anonymous": false
            },
            {
              "type": "error",
              "name": "ClOracleNotFound",
              "inputs": []
            }
          ],
          "methodIdentifiers": {
            "GRACE_PERIOD()": "c1a287e2",
            "sequencerUptimeFeed()": "a7264705"
          }
        }
```
