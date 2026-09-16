### Title
Oracle data-feed values used by AAs have no built-in freshness/staleness check - (File: data_feeds.js, formula/evaluation.js)

### Summary
ocore's `data_feed`/`in_data_feed` oscript primitives, which let an AA read a value posted by a trusted oracle address, are bounded only by ordering (`min_mci`/`max_mci`), never by time. There is no default protection against an AA silently consuming an outdated oracle value.

### Finding Description
`readDataFeedValue()` in `data_feeds.js` resolves an oracle's value by scanning stored `data_feed` messages between `min_mci` and `max_mci` (the current unit's mci) and simply returns the value found with the highest mci in that range, with no notion of "how old" that value is in real time: [1](#0-0) 
The function even accepts a `timestamp` parameter, annotated only "timestamp is for light only", but this value is never used anywhere inside the function body to enforce recency: [2](#0-1) 

When invoked from AA/oscript formulas, `min_mci` defaults to `0` unless the AA author explicitly supplies a bound, meaning an AA that omits `min_mci` will happily accept a value posted at the very beginning of the chain's history as "the" oracle value, with no freshness comparison against `mci` (current unit) or wall-clock time: [3](#0-2) [4](#0-3) 

Both the definition-language `in data feed` condition and the oscript `data_feed`/`in_data_feed` formulas expose only `min_mci` as an optional recency knob — there is no mandatory "max age" or "max mci distance from current mci" parameter enforced by the protocol itself: [5](#0-4) [6](#0-5) 

This exactly parallels the Compound `getPrice` issue: the underlying oracle primitive is trusted to be "current" without the consuming logic verifying that the returned round/value is actually fresh relative to now.

### Impact Explanation
Any AA that uses a `data_feed` value for consequential decisions (asset pricing, collateral valuation, payout calculation, liquidation eligibility — see the pattern used in `test/samples/futures_contract.oscript`) can be tricked or accidentally caused to use a stale price if the oracle stalls, is delayed, or an attacker structures a trigger to land right when the last posted feed value is old but still the "latest" in range. Because the AA's own author must remember to add an explicit `min_mci` (or equivalent time check) — and the protocol provides no default protection or even a documented recency signal — funds held by the AA can be drained or mispriced, i.e., **AA fund loss** through under/over-valued exchanges, exactly mirroring "liquidate safe positions or take out under-collateralized borrows" from the source report.

### Likelihood Explanation
Any unprivileged AA trigger sender can post a trigger whose timing determines which data feed value is "latest" for the query; if the oracle temporarily stops posting (network issue, oracle downtime, oracle operator error) the last stale value remains usable by any AA without complaint, and any AA author who forgets (or chooses not) to add strict `min_mci`/freshness bounds is silently exposed — this is a common omission pattern since the primitive doesn't require or default to a safe bound.

### Recommendation
Consider providing a first-class "freshness" parameter to `data_feed`/`in_data_feed` (e.g., a maximum allowed mci or timestamp distance from the current trigger's mci) that is validated by the protocol rather than left to convention, and update documentation/examples to make clear that omitting `min_mci` provides no staleness protection at all. Alternatively, surface the feed's own timestamp/mci to the AA response so authors can defensively bounce on stale data, and audit sample/reference contracts to always demonstrate an explicit staleness check.

### Proof of Concept
1. Oracle `O` posts `data_feed { price: 100 }` in unit `U1` at mci `M1`.
2. Oracle then stalls (no further updates) for an extended period; current mci advances to `M2 >> M1`.
3. An AA author writes `data_feed[[oracles='O', feed_name='price']]` without a `min_mci` bound (default `0`), as permitted by `formula/evaluation.js` (lines 602-646) and validated as acceptable by `formula/validation.js` (lines 26-39).
4. At mci `M2`, any user submits a trigger; the AA reads `price = 100` from `U1`, unaware that real market price has since diverged, and executes a payout/exchange based on the stale value — no error, no bounce, since ocore enforces no recency check beyond the (unset) `min_mci`.

### Citations

**File:** data_feeds.js (L204-211)
```javascript
// timestamp is for light only
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var start_time = Date.now();
	var objResult = { bAbortedBecauseOfSeveral: false, value: undefined, unit: undefined, mci: undefined };
	var bIncludeUnstableAAs = !!unstable_opts;
	var bIncludeAllUnstable = (unstable_opts === 'all_unstable');
	if (bIncludeUnstableAAs) {
```

**File:** formula/evaluation.js (L620-625)
```javascript
					if (params.min_mci) {
						min_mci = params.min_mci.value.toString();
						if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
							return cb("bad min_mci: "+min_mci);
						min_mci = parseInt(min_mci);
					}
```

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** definition.js (L401-412)
```javascript
			case 'in data feed':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!Array.isArray(args))
					return cb(op+" arg must be array");
				if (args.length !== 4 && args.length !== 5)
					return cb(op+" must have 4 or 5 args");
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4];
```

**File:** formula/validation.js (L26-39)
```javascript
function validateDataFeed(params) {
	var complexity = 1;
	if (params.oracles && params.feed_name) {
		for (var name in params) {
			var operator = params[name].operator;
			var value = params[name].value;
			if (Decimal.isDecimal(value)){
				if (!isFiniteDecimal(value))
					return {error: 'not finite', complexity};
				value = toDoubleRange(value).toString();
			}
			if (operator !== '=') return {error: 'not =', complexity};
			if (['oracles', 'feed_name', 'min_mci', 'feed_value', 'ifseveral', 'ifnone', 'what', 'type'].indexOf(name) === -1)
				return {error: 'unknown df param: ' + name, complexity};
```
