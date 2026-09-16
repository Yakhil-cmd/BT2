### Title
Data-feed key encoding via `0xFFFFFFFF - mci` silently corrupts key ordering/format once `main_chain_index` exceeds 2^32-1 - (File: `string_utils.js`)

### Summary
`string_utils.encodeMci()` builds the reverse-sortable suffix used in all data-feed KV keys (`df\n...` and `dfv\n...`) by computing `0xFFFFFFFF - mci` and hex-encoding it to a fixed 8-character string. This is the ocore analog of the JalaSwap `_update()` pattern: an implicit assumption that a counter fits into a 32-bit range, "reversed" for sort ordering, which was never wrapped in any bounds check. Unlike the Solidity case, JS integers don't revert on overflow, so the failure mode here is not a `revert`/DoS on a single call, but a silent corruption of the sort order and fixed-width key format once `mci` (an ever-increasing, unbounded main-chain index) surpasses `0xFFFFFFFF` (4,294,967,295).

### Finding Description
`encodeMci` and its inverse `getMciFromDataFeedKey` assume `mci <= 0xFFFFFFFF`: [1](#0-0) 

```
function encodeMci(mci){
	return (0xFFFFFFFF - mci).toString(16).padStart(8, '0'); // reverse order for more efficient sorting as we always need the latest
}

function getMciFromDataFeedKey(key){
	var arrParts = key.split('\n');
	var strReversedMci = arrParts[arrParts.length-1];
	var reversed_mci = parseInt(strReversedMci, 16);
	var mci = 0xFFFFFFFF - reversed_mci;
	return mci;
}
```

Once `mci > 0xFFFFFFFF`, `0xFFFFFFFF - mci` becomes negative. `Number.prototype.toString(16)` of a negative number produces a string with a leading `-` sign (e.g. `"-1"`), not an 8-hex-digit two's-complement wraparound like a real 32-bit unsigned subtraction would give. `padStart(8, '0')` on such a string does not restore the invariant either (e.g. `"-1"` → `"000000-1"`), producing a key suffix that:
- breaks the fixed 8-hex-char format relied upon by `getValueFromDataFeedKey`/`getMciFromDataFeedKey` (`m.length !== 6` splitting on `\n`, and `parseInt` of a malformed hex string with an embedded `-`),
- breaks the intended "reverse lexicographic order = latest MCI first" sort invariant that `readDataFeedValue`/`dataFeedByAddressExists` rely on when iterating the KV range for a given `(address, feed_name)`,
- is used identically in `main_chain.js` when writing data-feed entries during stabilization. [2](#0-1) 

The reversed-MCI keys are also read in the migration tool and in `data_feeds.js`'s range-scan logic that returns the highest/lowest MCI hit; a corrupted ordering there means the oracle-lookup logic used both directly in `data_feed()` formula evaluation and in `in_data_feed()` (used to gate AA state transitions and payment conditions) can return wrong/stale values or fail to find otherwise-present values, once `mci` grows past 2^32.

### Impact Explanation
`data_feed[[...]]` and `in_data_feed[[...]]` are core oscript primitives usable by any AA definition to read oracle-posted values, and they gate AA execution branches (`if` conditions), state updates, and payment amounts. If the reverse-MCI key ordering breaks:
- AAs relying on "most recent data feed value" semantics could read the wrong (stale or arbitrary) value instead of the latest one, because the KV range iteration order that the "reverse order for efficient latest-first sorting" comment depends on is violated.
- This can misprice AA-driven swaps/payments, incorrectly satisfy or fail `in_data_feed` conditions, and generally desynchronize different nodes' AA execution results if any node computes MCI differently around the rollover boundary, potentially causing node disagreement on AA response computation/validity.

This matches the class "node disagreement on validity/stability" or "AA fund loss" outcomes called out as acceptable Medium/High impacts in the rules.

### Likelihood Explanation
Likelihood is comparable to the referenced Sherlock finding: `main_chain_index` is a monotonically increasing counter with no configured cap, incremented on every stable main-chain unit. Reaching `0xFFFFFFFF` (≈4.29 billion) main-chain units requires an extremely long-running, high-throughput network — plausibly many decades away at current/foreseeable throughput, similar order of magnitude to the referenced 82–132-year timeframe for the Solidity `uint32` timestamp overflow. It is a certainty-if-the-network-survives-long-enough event, exactly the profile Sherlock accepted as Medium in the referenced finding. I could not fully verify every downstream consumer of `getMciFromDataFeedKey`/data-feed range scans, so the precise blast radius (partial mis-ordering only near the boundary vs. total corruption) is not proven end-to-end in this pass — this is stated as an open uncertainty.

### Recommendation
Use a proper 32-bit unsigned wraparound (or widen the encoding to a wider fixed-width field, e.g. 16 hex chars for a 64-bit-safe range) instead of relying on plain JS subtraction:
```js
function encodeMci(mci){
	return ((0xFFFFFFFF - mci) >>> 0).toString(16).padStart(8, '0');
}
```
This still breaks once `mci` truly exceeds `0xFFFFFFFF` (the `>>> 0` only fixes sign, not range), so the more robust fix is to widen the field width (e.g., use `Number.MAX_SAFE_INTEGER`-sized hex encoding, or migrate to a monotonic key scheme not based on subtraction from a fixed constant), and add an explicit guard/assertion that throws clearly instead of silently corrupting the key space when `mci` approaches the limit.

### Proof of Concept
```js
const string_utils = require('./string_utils.js');

// simulate an mci beyond the 32-bit boundary
const mci = 0x100000000; // 4294967296, one past 0xFFFFFFFF
console.log(string_utils.encodeMci(mci));
// => "-1" padded to "000000-1" -- not an 8-digit hex string,
// breaks the fixed 6-field format expected by getValueFromDataFeedKey
// and the reverse-sort-order invariant used by data feed range scans.

console.log(string_utils.getMciFromDataFeedKey('df\naddr\nfeed\nn\nvalue\n000000-1'));
// parseInt('000000-1', 16) => NaN -> mci computed as NaN, corrupting lookups
```

### Citations

**File:** string_utils.js (L63-73)
```javascript
function encodeMci(mci){
	return (0xFFFFFFFF - mci).toString(16).padStart(8, '0'); // reverse order for more efficient sorting as we always need the latest
}

function getMciFromDataFeedKey(key){
	var arrParts = key.split('\n');
	var strReversedMci = arrParts[arrParts.length-1];
	var reversed_mci = parseInt(strReversedMci, 16);
	var mci = 0xFFFFFFFF - reversed_mci;
	return mci;
}
```

**File:** main_chain.js (L1592-1616)
```javascript
										throw Error("no author addresses in "+unit);
									var strMci = string_utils.encodeMci(mci);
									for (var feed_name in payload){
										var value = payload[feed_name];
										var strValue = null;
										var numValue = null;
										if (typeof value === 'string'){
											strValue = value;
											var bLimitedPrecision = (mci < constants.aa2UpgradeMci);
											var float = string_utils.toNumber(value, bLimitedPrecision);
											if (float !== null)
												numValue = string_utils.encodeDoubleInLexicograpicOrder(float);
										}
										else
											numValue = string_utils.encodeDoubleInLexicograpicOrder(value);
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
									}
```
