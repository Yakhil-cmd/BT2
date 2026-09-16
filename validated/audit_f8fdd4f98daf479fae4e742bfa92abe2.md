Based on the ocore data-feed evaluation code, there is a directly analogous pattern to the Chainlink staleness bug.

### Title
oscript `data_feed[[...]]` returns arbitrarily old feed values with no default freshness/staleness check, allowing AAs that price assets off it to use stale data - (File: `formula/evaluation.js`, `data_feeds.js`)

### Summary
The Chainlink report flags that `latestRoundData()` was consumed for pricing without checking `updatedAt`, so a stale price could silently be used. ocore's oscript `data_feed[[...]]` primitive has the same failure mode by default: it returns the "last" matching feed value found anywhere between `min_mci` (default `0`) and the current `mci`, with no enforced recency check, and `what=value` (the default) does not even expose the timestamp/mci of the returned value to the caller.

### Finding Description
`readDataFeedValue` in `data_feeds.js` searches the key-value store for a data feed entry between `min_mci` and `max_mci`: [1](#0-0) 
When called from oscript's `data_feed` case in `formula/evaluation.js`, `min_mci` defaults to `0` if the AA author does not specify it: [2](#0-1) 
and `what` defaults to `'value'`, returning only the raw value — not the unit or mci at which it was posted — unless the author explicitly requests `what='unit'`: [3](#0-2) 
`readDataFeedByAddress` picks whichever record satisfies `ifseveral` (default `'last'`) within that unbounded `[0, mci]` range, with no requirement that the matched record be recent relative to `timestamp`/`mci`: [4](#0-3) 

Because `min_mci` defaults to `0`, an AA author who writes `data_feed[[oracles=..., feed_name=...]]` for pricing (exactly analogous to calling `latestRoundData()` and only reading `answer`) will silently receive the most recent value ever posted, even if the referenced oracle has stopped updating for a long time (oracle downtime, decommissioning, etc.). Nothing in the primitive itself forces the caller to compare `timestamp`/`mci` against the returned data's freshness unless the author manually fetches `what='unit'` and then separately checks the unit's timestamp — an opt-in pattern, not the default. This mirrors the exact root cause in the reported issue: the value is retrieved without the metadata needed to validate recency, and the trivial call site silently accepts old data.

### Impact Explanation
Any AA that reads a price/exchange-rate via `data_feed[[...]]` without explicitly adding `min_mci`/timestamp-freshness checks can be triggered (by any unprivileged trigger sender) at a time when the oracle feed is stale, causing the AA to misprice assets it issues, exchanges, or uses for collateral decisions. This can lead to fund loss for the AA (paying out at a stale/incorrect rate) or unfair value extraction by whoever posts the trigger during the stale window — matching the "AA fund loss" impact class.

### Likelihood Explanation
This is triggerable by any address that can post a trigger unit to the AA; no privileged access, malicious oracle, or malicious node is required — only that the referenced oracle has not posted a fresh value recently (a condition that occurs naturally whenever an oracle bot goes offline or is decommissioned). The example bundled test/sample contract (`futures_contract.oscript`) already demonstrates that developers are expected to manually guard against "the exchange rate not posted yet" by inspecting `var['blackswan']`/timestamp logic — showing this is a known, easy-to-miss burden placed on AA authors rather than something enforced by the primitive itself: [5](#0-4) 

### Recommendation
Consider exposing feed recency more directly by default (e.g., always returning the mci/timestamp of the matched record alongside the value, or requiring an explicit `min_mci`/`max_age` parameter) so pricing logic cannot trivially omit a staleness check the way `_etherPrice()` did in the Chainlink report. At minimum, document prominently that `data_feed[[...]]` without `min_mci`/unit-based timestamp checks is unsafe for pricing.

### Proof of Concept
1. Oracle address `O` posts `feed_name='RATE'` at `mci=100` with value `10`, then stops posting entirely.
2. An AA is defined with logic such as `$rate = data_feed[[oracles='O', feed_name='RATE']]; ... use $rate to price an exchange`.
3. Months later, at `mci=100000`, a user posts a trigger to the AA. `readDataFeedValue` is called with `min_mci=0, max_mci=100000`, matches the record from `mci=100`, and returns `10` with no indication to the AA logic that this value is far out of date.
4. The AA executes its payout/exchange logic using the stale rate `10`, even though the real-world price has since diverged significantly, causing mispriced exchange and potential fund loss to the AA (or to other users of the AA), exactly as the Chainlink report describes for `_etherPrice()`.

### Citations

**File:** data_feeds.js (L205-211)
```javascript
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var start_time = Date.now();
	var objResult = { bAbortedBecauseOfSeveral: false, value: undefined, unit: undefined, mci: undefined };
	var bIncludeUnstableAAs = !!unstable_opts;
	var bIncludeAllUnstable = (unstable_opts === 'all_unstable');
	if (bIncludeUnstableAAs) {
```

**File:** data_feeds.js (L287-330)
```javascript
function readDataFeedByAddress(address, feed_name, value, min_mci, max_mci, ifseveral, objResult, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var bAbortIfSeveral = (ifseveral === 'abort');
	var key_prefix;
	if (value === null){
		key_prefix = 'dfv\n'+address+'\n'+feed_name;
	}
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
	var options = {
		gte: key_prefix+'\n'+string_utils.encodeMci(max_mci),
		lte: key_prefix+'\n'+string_utils.encodeMci(min_mci),
		limit: bAbortIfSeveral ? 2 : 1
	};
	var handleData = function(data){
		if (bAbortIfSeveral && objResult.value !== undefined){
			objResult.bAbortedBecauseOfSeveral = true;
			return;
		}
		var mci = string_utils.getMciFromDataFeedKey(data.key);
		if (objResult.value === undefined || ifseveral === 'last' && mci > objResult.mci){
			if (value !== null){
				objResult.value = string_utils.getValueFromDataFeedKey(data.key);
				objResult.unit = data.value;
			}
			else{
				var arrParts = data.value.split('\n');
				objResult.value = string_utils.getFeedValue(arrParts[0], bLimitedPrecision); // may convert to number
				objResult.unit = arrParts[1];
			}
			objResult.mci = mci;
		}
	};
```

**File:** formula/evaluation.js (L611-625)
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
					if (params.min_mci) {
						min_mci = params.min_mci.value.toString();
						if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
							return cb("bad min_mci: "+min_mci);
						min_mci = parseInt(min_mci);
					}
```

**File:** formula/evaluation.js (L632-656)
```javascript
					var what = 'value';
					if (params.what){
						what = params.what.value;
						if (what !== 'unit' && what !== 'value')
							return cb("bad what: "+what);
					}
					var type = 'auto';
					if (params.type){
						type = params.type.value;
						if (type !== 'string' && type !== 'auto')
							return cb("bad df type: "+type);
					}
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
```

**File:** test/ojson.test.js (L1063-1073)
```javascript
					if (var['blackswan'])
						$bytes = $usd_asset_amount;
					else{
						if (timestamp < 1556668800)
							bounce('wait for maturity date');
						// data_feed will abort if the exchange rate not posted yet
						$exchange_rate = data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']];
						$bytes_per_usd_asset = min(50/$exchange_rate/2, 1);
						$bytes_per_gb_asset = 1 - $bytes_per_usd_asset;
						$bytes = round($bytes_per_usd_asset * $usd_asset_amount + $bytes_per_gb_asset * $gb_asset_amount);
					}
```
