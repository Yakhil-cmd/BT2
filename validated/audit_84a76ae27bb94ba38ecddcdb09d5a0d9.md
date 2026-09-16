### Title
Type-confusion in data-feed equality check via unchecked `toString()` comparison - (File: `data_feeds.js`)

### Summary
`data_feeds.js` implements the value-matching logic behind the oscript/AA `data_feed[[...]]` and `in_data_feed[[...]]` formula operators. For the `=`/`!=` relations on *unstable* AA-authored data feeds, equality is decided with `value.toString() === feed_value.toString()` instead of a type-aware comparison. This mirrors the root cause of CVE-2018-20226 (a security-relevant equality decision delegated to an unreviewed/implicit string conversion instead of a correct type-checked comparison), just in ocore's oracle/data-feed trust layer instead of Cortex's `Role` model.

### Finding Description
`dataFeedExists()` and `readDataFeedValue()` both special-case `bAA`/unstable data feeds (data feeds posted by other, not-yet-stable AA response units) and match the caller-supplied `value` against a feed's `feed_value` using: [1](#0-0) [2](#0-1) 

`value` is not a fixed literal — it is the evaluated result of an oscript expression passed as the `feed_value` parameter to the `data_feed`/`in_data_feed` operators, and can be derived from attacker-controlled trigger data (`trigger.data.*`) because the evaluator only enforces `isValidValue` (string/number, boolean excluded for this param) before invoking `getDataFeed`/`dataFeeds.readDataFeedValue`: [3](#0-2) [4](#0-3) 

Because equality falls back to `.toString()` rather than requiring identical JS type *and* value, a numeric feed value and a differently-typed feed value that happen to stringify identically (e.g. number `0` posted by one upstream AA vs. a different representation later, or a string that looks numeric vs. an actual number) are treated as equal. This breaks the type-safety guarantee that AA authors rely on when using `data_feed`/`in_data_feed` as a gate for state transitions (e.g., "has oracle X already reported outcome Y for this round", "is this claim id already marked used"). An attacker who controls the query-side value (via trigger data fed into the formula) can cause the equality check to spuriously succeed against a feed value of a different type that was never intended to match, letting a branch of AA logic execute (fund transfer, state flag set) under a condition the AA author believed was strictly type-checked — the same class of "trusted object's stringified form used for a security decision" defect as the original CVE's un-overridden `Role.toString()`.

### Impact Explanation
If an AA's oscript logic uses `data_feed[[...]]` / `in_data_feed[[...]]` results to gate payouts, mark claims as fulfilled, or check "has this key already been used" (a common double-spend/replay guard pattern for AAs), the toString()-based type confusion can let an attacker-influenced query value match a feed value of a different, unintended type. This can cause an AA to release funds under a condition that was not actually met, or fail to recognize a distinct value as distinct, leading to AA fund loss/incorrect fund distribution.

### Likelihood Explanation
Exploitability requires: (1) an AA design that keys security-relevant branching on `data_feed`/`in_data_feed` equality against a value partially influenced by trigger data, and (2) the compared values differing in JS type (string vs number) while sharing a `toString()` representation. This is a plausible but AA-design-dependent condition — it is not a universal, always-exploitable bug in ocore itself, but a real weakness in the primitive that AA authors depend on for correctness. I could not find a concrete in-repo AA/oscript template that already combines these conditions to produce a guaranteed unauthorized-spend, so confidence in a fully self-contained PoC is moderate rather than proven.

### Recommendation
Replace the `toString()`-based equality in `data_feeds.js` (`dataFeedExists` and `readDataFeedValue`, unstable/`bAA` branches) with a type-aware comparison: require `typeof value === typeof feed_value` before comparing, or normalize both sides through the same canonical numeric/string parsing used elsewhere in the file (`string_utils.toNumber`) instead of relying on JS's default string coercion.

### Proof of Concept
Conceptual (design-dependent, not a guaranteed universal exploit):
1. AA `B` reads an oracle result from unstable AA `A`'s response via `in_data_feed[[oracles=A, feed_name='claimed_id', feed_value=$trigger.data.id]]` to check "has this id already been claimed", where `$trigger.data.id` is attacker-supplied.
2. AA `A` previously posted `feed_value = 123` (number) for a genuine claim.
3. Attacker sends a trigger to `B` with `data.id` set to a value whose formula evaluation yields a number/string that differs from `123` in type but stringifies identically under `.toString()`, causing `dataFeedExists()` at [1](#0-0)  to report a spurious match (or spurious non-match, depending on which branch the AA gates), bypassing the intended replay/uniqueness guard and allowing a claim to be processed twice or a payout condition to trigger incorrectly.

### Citations

**File:** data_feeds.js (L51-54)
```javascript
				if (relation === '=') {
					if (value === feed_value || value.toString() === feed_value.toString())
						bFound = true;
					return;
```

**File:** data_feeds.js (L230-233)
```javascript
					return;
				var feed_value = payload[feed_name];
				if (value === null || value === feed_value || value.toString() === feed_value.toString())
					arrCandidates.push({
```

**File:** formula/evaluation.js (L611-619)
```javascript
					var value = null;
					var relation = '';
					var min_mci = 0;
					if (params.feed_value) {
						value = params.feed_value.value;
						relation = params.feed_value.operator;
						if (!isValidValue(value))
							return cb("bad feed_value: "+value);
					}
```

**File:** formula/evaluation.js (L644-663)
```javascript
					if (params.ifnone && !isValidValue(params.ifnone.value))
						return cb("bad ifnone: "+params.ifnone.value);
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
					//	console.log(arrAddresses, feed_name, value, min_mci, ifseveral);
					//	console.log('---- objResult', objResult);
						if (objResult.bAbortedBecauseOfSeveral)
							return cb("several values found");
						if (objResult.value !== undefined){
							if (what === 'unit')
								return cb(null, objResult.unit);
							if (type === 'string')
								return cb(null, objResult.value.toString());
							return cb(null, (typeof objResult.value === 'string') ? objResult.value : createDecimal(objResult.value));
						}
						if (params.ifnone && params.ifnone.value !== 'abort'){
						//	console.log('===== ifnone=', params.ifnone.value, typeof params.ifnone.value);
							return cb(null, params.ifnone.value); // the type of ifnone (string, decimal, boolean) is preserved
						}
						cb("data feed " + feed_name + " not found");
					});
```
