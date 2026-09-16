## Title
Data feed value-matching inconsistency between unstable (in-memory) and stable (KV-store) lookup paths lets an oracle bypass `in_data_feed`/`data_feed` AA conditions - (File: data_feeds.js)

### Summary
The reported Node.js bug is a class of *inconsistent-matching* vulnerability: one code path (the "fast"/candidate check) uses a looser or different equality rule than the authoritative/canonical path, so the same underlying data is judged "matching" by one path and "not matching" by the other, breaking a trust decision. `ocore` has an exact structural analog in the data-feed engine used by both address definitions (`in data feed`) and AA formulas (`data_feed`/`in_data_feed`): the unstable, in-memory candidate scan compares values with naive `toString()` equality, while the canonical, persisted KV-store lookup parses values numerically and compares them via a normalized lexicographic encoding. The two comparisons disagree on numerically-equal-but-differently-formatted values (e.g. `10` vs `"10.0"`, `"010"`, `"1e1"`, `"+10"`).

### Finding Description
`dataFeedExists()` and `readDataFeedValue()` in `data_feeds.js` each implement two different matching mechanisms:

1. **Unstable/in-memory fast path** (used only `bAA===true`, i.e. from AA formula evaluation): matches by raw JS coercion. [1](#0-0) 
and, in `readDataFeedValue`: [2](#0-1) 

2. **Stable/KV-store canonical path**: values are parsed to numbers with `string_utils.toNumber()` and compared through a byte-for-byte lexicographic double encoding, so formatting differences vanish: [3](#0-2) 
and in `readDataFeedByAddress`: [4](#0-3) 

The numeric normalization used by the canonical path (`string_utils.toNumber`, `encodeDoubleInLexicograpicOrder`) treats `10`, `"10.0"`, `"010"`, `"+10"`, `"1e1"` as the *same* value: [5](#0-4) [6](#0-5) 

But the unstable-path comparison (`value === feed_value || value.toString() === feed_value.toString()`) treats them as *different* unless the string representations are byte-identical. Consequently, whether a specific oracle-posted `data_feed` value is judged "equal" to a queried value in an `in_data_feed`/`data_feed` AA condition depends on whether that oracle's unit is still unstable (fast path) or already stable (canonical path) at the moment the AA response is computed - exactly the kind of dual-mechanism inconsistency that classically produces trust-policy bypasses.

This function is reached whenever an AA formula uses `data_feed[[...]]` or `in_data_feed[[...]]`, which pulls in the unstable-aware code path via the `bAA` flag in `formula/evaluation.js` (`dataFeeds.dataFeedExists(..., bAA, cb)` / `dataFeeds.readDataFeedValue(..., unstable_opts, ...)`), i.e. it executes on every trigger sent to any AA that reads a data feed - a fully unprivileged, attacker-reachable path (any address can be both a trigger sender and, if referenced as an oracle by the AA definition — e.g. self-oracle or user-supplied oracle address patterns — the poster of the compared data feed).

### Impact Explanation
An AA that relies on `in_data_feed`/`data_feed` equality to gate fund release, prevent double-processing of a payment/order id, or check an oracle-reported outcome can be tricked into evaluating the wrong boolean because the "is this value already recorded"/"does this value match" check silently disagrees with what the persisted, canonical data actually contains. Typical exploitable patterns:
- An AA guard such as `!in_data_feed[[..., feed_value=trigger.data.amount]]` intended to block duplicate payouts can be defeated by having the guard oracle post the previous value in a differently-formatted (but numerically identical) form while it is still unstable, causing the AA to treat a duplicate trigger as novel → double payout / fund loss.
- Conversely, a condition intended to release funds on a genuine data feed match can be spuriously blocked, freezing AA funds.

This satisfies the "AA fund loss or freezing" impact bar.

### Likelihood Explanation
Exploitation requires no special privilege: only the ability to post a `data_feed` message (an unprivileged oracle role, often the trigger sender itself in common AA templates) and a normal AA trigger. Formatting numeric strings differently (leading zero, trailing `.0`, exponential notation, explicit `+` sign) is trivial and entirely under attacker control, and the timing window where a data-feed message is "unstable" (the fast-path condition) is common in practice because AAs frequently react to oracle posts within the same batch of units.

### Recommendation
Unify the two comparison implementations: make the unstable/in-memory fast path in `dataFeedExists()` and `readDataFeedValue()` use the same numeric normalization (`string_utils.toNumber` + numeric equality, or reuse `getFeedValue`) as the canonical KV-store path, rather than naive `toString()` comparison, so that "equal" is defined identically regardless of a message's stability status.

### Proof of Concept
1. Deploy an AA that includes a guard: `bounce_if(in_data_feed[[oracles="ORACLE_ADDR", feed_name="processed_id", feed_value=trigger.data.id]])`, intended to prevent processing the same `id` twice.
2. Oracle (attacker-controlled or externally influenced) posts `data_feed{processed_id: "5.0"}` in a unit that is not yet stable.
3. Attacker sends a trigger with `data.id = 5` (a number) while the oracle's unit is still unstable.
4. `dataFeedExists(..., bAA=true, ...)` hits the unstable branch: `5 === "5.0"` is false, and `"5".toString() === "5.0".toString()` → `"5" === "5.0"` is false ⇒ `bFound=false`; the guard does not trigger, so the AA processes the trigger even though, once the oracle's unit stabilizes, `readDataFeedByAddress`/`dataFeedByAddressExists` would have parsed `"5.0"` to numeric `5` and matched `trigger.data.id=5` exactly.
5. The AA has now processed `id=5` even though it should have been blocked as already-processed, demonstrating the double-processing / fund-loss primitive caused purely by the matching inconsistency between the unstable and stable code paths.

### Citations

**File:** data_feeds.js (L51-55)
```javascript
				if (relation === '=') {
					if (value === feed_value || value.toString() === feed_value.toString())
						bFound = true;
					return;
				}
```

**File:** data_feeds.js (L119-136)
```javascript
	var prefixed_value;
	var type;
	if (typeof value === 'string'){
		var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
		var float = string_utils.toNumber(value, bLimitedPrecision);
		if (float !== null){
			prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(float);
			type = 'n';
		}
		else{
			prefixed_value = 's\n'+value;
			type = 's';
		}
	}
	else{
		prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(value);
		type= 'n';
	}
```

**File:** data_feeds.js (L228-240)
```javascript
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
				var feed_value = payload[feed_name];
				if (value === null || value === feed_value || value.toString() === feed_value.toString())
					arrCandidates.push({
						value: string_utils.getFeedValue(feed_value, bLimitedPrecision),
						latest_included_mc_index: objUnit.latest_included_mc_index,
						level: objUnit.level,
						unit: objUnit.unit,
						mci: max_mci // it doesn't matter
					});
			});
```

**File:** data_feeds.js (L294-306)
```javascript
	else{
		var prefixed_value;
		if (typeof value === 'string'){
			var float = string_utils.toNumber(value, bLimitedPrecision);
			if (float !== null)
				prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(float);
			else
				prefixed_value = 's\n'+value;
		}
		else
			prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(value);
		key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
	}
```

**File:** string_utils.js (L86-104)
```javascript
function toNumber(value, bLimitedPrecision) {
	if (typeof value === 'number')
		return value;
	if (bLimitedPrecision)
		return getNumericFeedValue(value);
	if (typeof value !== 'string')
		throw Error("toNumber of not a string: "+value);
	var m = value.match(/^[+-]?(\d+(\.\d+)?)([eE][+-]?(\d+))?$/);
	if (!m)
		return null;
	var f = parseFloat(value);
	if (!isFinite(f))
		return null;
	var mantissa = m[1];
	var abs_exp = m[4];
	if (f === 0 && mantissa > 0 && abs_exp > 0) // too small number out of range such as 1.23e-700
		return null;
	return f === 0 ? 0 : f; // replace -0
}
```

**File:** string_utils.js (L141-152)
```javascript
function encodeDoubleInLexicograpicOrder(float){
	if (float === -0) // it is actually true for both 0's
		float = 0; // we always assign a positive 0
	var buf = Buffer.allocUnsafe(8);
	buf.writeDoubleBE(float, 0);
	if (float >= 0)
		buf[0] ^= 0x80; // flip the sign bit
	else
		for (var i=0; i<buf.length; i++)
			buf[i] ^= 0xff; // flip the sign bit and reverse the ordering
	return buf.toString('hex');
}
```
