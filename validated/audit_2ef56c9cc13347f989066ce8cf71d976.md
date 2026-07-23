### Title
Single `MAX_REF_STALENESS` Applied to Both Legs of Synthetic Pair Allows Stale Price to Reach Pool Swap - (File: `smart-contracts-poc/contracts/AnchoredPriceProvider.sol`)

### Summary

`AnchoredPriceProvider` supports a two-feed synthetic ratio mode (e.g., BTC/USD ÷ ETH/USD = BTC/ETH). Both legs are staleness-checked against the single immutable `MAX_REF_STALENESS` set at construction. Because the `AnchoredProviderFactory` keys its envelope validation only on `baseFeedId`, the quote feed's actual heartbeat is never considered. When the two feeds have materially different update frequencies, setting `MAX_REF_STALENESS` to the slower feed's heartbeat silently allows the faster feed to be stale, producing a corrupted synthetic ratio that reaches every pool swap.

### Finding Description

`_readLeg` is the shared staleness gate for both legs:

```solidity
// AnchoredPriceProvider.sol  _readLeg()
if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS))
    return (mid, spreadBps, refTime, false);
``` [1](#0-0) 

`_getBidAndAskPrice` calls `_readLeg` for both `baseFeedId` and `quoteFeedId` with the same threshold:

```solidity
(uint256 mid,  uint256 spreadBps,  , bool ok)  = _readLeg(baseFeedId);
...
(uint256 mid2, uint256 spreadBps2, , bool ok2) = _readLeg(_quote);
``` [2](#0-1) 

`MAX_REF_STALENESS` is a single immutable set at construction: [3](#0-2) 

The `AnchoredProviderFactory` validates `maxRefStaleness` exclusively against the **base feed's** class envelope — the quote feed has no envelope, no class, and no independent staleness bound:

```solidity
bytes32 classId = feedClass[baseFeedId];   // quote feed never consulted
...
|| maxRefStaleness < env.stalenessMin || maxRefStaleness > env.stalenessMax
``` [4](#0-3) 

The factory comment confirms this design gap explicitly:

> "The envelope is keyed on `baseFeedId` (the provider's class); the ref feed only contributes its uncertainty and is validated for existence at provider construction." [5](#0-4) 

### Impact Explanation

When `MAX_REF_STALENESS` is set to match the slower feed's heartbeat (the natural choice to avoid unnecessary halts on that leg), the faster feed can be arbitrarily stale within that window. The corrupted mid price propagates directly into the synthetic ratio:

```solidity
mid = Math.mulDiv(mid, ORACLE_DECIMALS, mid2);   // stale mid1 or mid2
spreadBps += spreadBps2;
``` [6](#0-5) 

The wrong ratio then sets the reference band (`refBid`/`refAsk`), and every swap through the pool executes against that stale band. Traders can extract value from the pool (or be overcharged) proportional to the price drift of the stale leg over the staleness window. This is a direct bad-price execution impact: a stale bid/ask quote reaches a live pool swap.

### Likelihood Explanation

- `createAnchoredProvider` is permissionless; any address can deploy a synthetic provider.
- The curator has no on-chain signal about the quote feed's heartbeat — the factory provides no per-leg staleness field and no warning.
- Setting `MAX_REF_STALENESS` to the slower feed's heartbeat is the rational choice to keep the pool live; the curator is not acting maliciously.
- Chainlink Data Streams and Pyth Lazer feeds used in this system have materially different update frequencies (seconds for HFS feeds, minutes/hours for standard feeds), making mismatched synthetic pairs a realistic deployment scenario.

### Recommendation

Add a second staleness parameter `maxQuoteRefStaleness` to `AnchoredPriceProvider` and `AnchoredProviderFactory`. Apply it exclusively to the quote leg in `_readLeg`. The factory should validate it against a quote-feed class envelope (or at minimum against the same `MAX_STALENESS` hard cap). If a single parameter is kept for simplicity, document explicitly that it must be set to `min(baseFeedHeartbeat, quoteFeedHeartbeat)` and enforce this via a separate quote-feed class lookup in the factory.

### Proof of Concept

1. Admin configures envelope for `BTC_CLASS`: `stalenessMin=0`, `stalenessMax=86400` (24 h).
2. Curator calls `createAnchoredProvider(oracle, BTC_USD_FEED, ETH_USD_FEED, ..., maxRefStaleness=86400, ...)`. BTC/USD has a 1-hour heartbeat; ETH/USD has a 24-hour heartbeat. Setting 24 h avoids halting on the ETH leg.
3. BTC/USD oracle is not pushed for 23 hours (within `MAX_REF_STALENESS=86400`). ETH/USD is fresh.
4. Pool calls `getBidAndAskPrice()` → `_getBidAndAskPrice()` → `_readLeg(BTC_USD_FEED)`.
5. `_isStale(refTime=now-23h, now, 86400)` → `23*3600 <= 86400` → **not stale** → stale BTC price passes.
6. Synthetic mid = `stale_BTC_price / fresh_ETH_price` — potentially 23 hours of BTC drift baked in.
7. `_computeBidAsk` builds the reference band from this corrupted mid; `getBidAndAskPrice` returns it without revert.
8. Every swap in the pool executes against the stale band, allowing arbitrageurs to drain the pool's liquidity at the expense of LPs.

### Citations

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L75-78)
```text
    /// @notice Reference older than this (seconds) halts quoting — never clamp to a stale anchor.
    ///         Zero means the reference must be in the current block (refTime == block.timestamp).
    uint256 public immutable MAX_REF_STALENESS;
    /// @notice Circuit breaker: reference uncertainty above this (bps) means the feed is broken — halt.
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L258-272)
```text
    function _getBidAndAskPrice() internal returns (uint128, uint128) {
        (uint256 mid, uint256 spreadBps, , bool ok) = _readLeg(baseFeedId);
        if (!ok) return (0, type(uint128).max);

        bytes32 _quote = quoteFeedId;
        if (_quote != bytes32(0)) {
            (uint256 mid2, uint256 spreadBps2, , bool ok2) = _readLeg(_quote);
            if (!ok2 || mid2 == 0) return (0, type(uint128).max);
            // Synthetic ratio (8-decimal): mid1 / mid2. Relative uncertainties of a ratio add.
            mid = Math.mulDiv(mid, ORACLE_DECIMALS, mid2);
            spreadBps += spreadBps2;
        }

        return _computeBidAsk(mid, spreadBps);
    }
```

**File:** smart-contracts-poc/contracts/AnchoredPriceProvider.sol (L277-295)
```text
    function _readLeg(bytes32 feedId)
        internal returns (uint256 mid, uint256 spreadBps, uint256 refTime, bool ok)
    {
        (mid, spreadBps, , refTime) = IPricedOracle(address(offchainOracle)).price(feedId, msg.sender);

        // Stale reference → not ok. Clamping to a stale anchor is the one false-safety case.
        if (_isStale(refTime, block.timestamp, MAX_REF_STALENESS)) return (mid, spreadBps, refTime, false);

        // Basic validity — mid positive, spreadBps not the stalled/off-hours marker (the Chainlink oracle
        // writes spreadBps = ORACLE_BPS when an RWA market is closed).
        if (mid == 0 || spreadBps >= ORACLE_BPS) return (mid, spreadBps, refTime, false);

        // Per-leg price guard.
        (uint128 guardMin, uint128 guardMax) = offchainOracle.priceGuard(feedId);
        guardMax = guardMax == 0 ? type(uint128).max : guardMax;
        if (mid < guardMin || mid > guardMax) return (mid, spreadBps, refTime, false);

        ok = true;
    }
```

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L153-155)
```text
    /// @param quoteFeedId optional second feed for synthetic ratio quoting (zero = single-feed). The
    ///        envelope is keyed on `baseFeedId` (the provider's class); the ref feed only contributes its
    ///        uncertainty and is validated for existence at provider construction.
```

**File:** smart-contracts-poc/contracts/AnchoredProviderFactory.sol (L171-180)
```text
        bytes32 classId = feedClass[baseFeedId];
        if (classId == bytes32(0)) classId = DEFAULT_CLASS;

        Envelope storage env = envelopes[classId];
        if (!env.exists) revert EnvelopeNotFound(classId);
        if (
            minMargin < env.minMarginMin || minMargin > env.minMarginMax
            || maxRefStaleness < env.stalenessMin || maxRefStaleness > env.stalenessMax
            || maxSpreadBps < env.maxSpreadMin || maxSpreadBps > env.maxSpreadMax
        ) revert ParamsOutOfEnvelope();
```
