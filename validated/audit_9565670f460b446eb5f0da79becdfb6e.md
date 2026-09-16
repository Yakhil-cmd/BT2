### Title
Missing default freshness/staleness check on `data_feed` oracle reads lets AA-based price/auction logic execute using arbitrarily stale values during oracle downtime - (File: `data_feeds.js`)

### Summary
The reported bug is a Dutch-auction contract that has no way to detect that its time-source (the L2 sequencer) has stopped producing blocks, so the auction either fails to attract bids or is forced to settle at a stale/unfavorable price once the sequencer resumes. The analogous weakness in ocore is that the `data_feed[[...]]` oscript operator and its underlying `readDataFeedValue`/`readDataFeedByAddress` functions in `data_feeds.js` have **no built-in mechanism to detect or reject a stale oracle** feed. They always return the most recent value found within `[min_mci, max_mci]`, no matter how old it is, unless the AA author manually and correctly bounds `min_mci` to a value that anticipates the exact MCI expected at execution time — which is generally impractical because MCI advancement rate is not fixed and cannot be predicted in advance.

### Finding Description
`data_feed[[oracles=..., feed_name=...]]` is evaluated in `formula/evaluation.js` by calling `dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, cb)` [1](#0-0) . `readDataFeedValue` in turn delegates to `readDataFeedByAddress`, which simply performs a range query over `[min_mci, max_mci]` and returns whichever value satisfies `ifseveral` (defaulting to `'last'`, i.e. the most recently posted value in that window) [2](#0-1) . `min_mci` defaults to `0` if not supplied by the AA author [3](#0-2) [4](#0-3) , meaning the *entire history* of the feed is eligible, and the freshest available post — however old — will always be returned as long as it exists.

There is no protocol-level notion of "the oracle must have posted within the last N seconds/MCIs" analogous to a sequencer-uptime check. The only way an AA developer can bound recency is to hardcode a `min_mci` computed from an *a priori* guess of the future MCI at trigger time, which the sample contract shipped in the codebase does not even attempt: `test/samples/futures_contract.oscript` reads `data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']]` with no `min_mci` at all and computes a payout amount directly from it [5](#0-4) . The comment "`data_feed will abort if the exchange rate not posted yet`" shows the only failure mode the authors considered is *never posted*, not *posted long ago and now stale because the oracle has gone offline*.

### Impact Explanation
Any AA that uses a `data_feed` value to price a swap, settle a futures/option-like contract, or drive a time/price decay mechanism (the direct analog of the Dutch auction in the report) is exposed to executing at a bad price if the oracle address stops posting fresh updates (oracle downtime, oracle key compromise/inactivity, network conditions preventing the oracle operator from posting, etc.), because the AA has no protocol-enforced way to detect "the data feed has gone stale" and will happily use the last known value as if it were current. This can cause direct fund loss for one counterparty of the AA (e.g., users converting assets at an outdated exchange rate long after the market has moved), which is the same "loss due to no liveness/uptime check for a time-critical external dependency" root cause identified in the original finding, translated into ocore's data-feed/AA execution model.

### Likelihood Explanation
This requires an oracle to stop posting fresh data for an extended period while an AA that depends on its feed for pricing remains reachable/triggerable by any user's payment — a realistic operational condition (oracle downtime, deprecated feed, operator negligence) rather than an attack requiring special privileges. Any unprivileged AA trigger sender can submit a payment that causes the AA to read the stale feed and execute the resulting (bad) price, exactly mirroring the "auction stuck with only bad-priced bids available after the outage" scenario in the report.

### Recommendation
Provide oscript/AA authors with a first-class primitive to check feed freshness (e.g., an easy way to fetch "MCI or timestamp of last post" alongside the value, and require/encourage AAs to bounce if `mci - last_post_mci` exceeds an app-specific threshold), and update documentation/sample contracts (like `futures_contract.oscript`) to always enforce a freshness bound instead of relying purely on "posted or not". Consider also warning at AA-validation time when a `data_feed` read has no `min_mci`/freshness bound at all for price-sensitive computations.

### Proof of Concept
1. Deploy an AA that reads `data_feed[[oracles=<oracle_addr>, feed_name='PRICE']]` without a `min_mci` bound (as in `test/samples/futures_contract.oscript`) and uses the value to compute a payout/exchange amount [5](#0-4) .
2. The oracle posts a price at MCI `X` and then stops posting (goes offline, key lost, etc.) for a long period during which the real market price moves significantly.
3. A user submits a trigger payment to the AA at MCI `X + N` (much later). `readDataFeedValue`/`readDataFeedByAddress` will still return the price value from MCI `X`, because `min_mci` defaults to `0` and `ifseveral='last'` simply picks the most recent (but stale) entry [2](#0-1) .
4. The AA executes using the stale price, producing an output that is favorable to the trigger sender and a loss to the AA/protocol (or vice versa), with no built-in mechanism having flagged the staleness.

### Citations

**File:** formula/evaluation.js (L620-625)
```javascript
					if (params.min_mci) {
						min_mci = params.min_mci.value.toString();
						if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
							return cb("bad min_mci: "+min_mci);
						min_mci = parseInt(min_mci);
					}
```

**File:** formula/evaluation.js (L646-663)
```javascript
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

**File:** data_feeds.js (L361-366)
```javascript
	var min_mci = 0;
	if ('min_mci' in params) {
		min_mci = params.min_mci;
		if (!ValidationUtils.isNonnegativeInteger(min_mci))
			return cb("bad min_mci: " + util.inspect(min_mci, { depth: 5 }));
	}
```

**File:** test/samples/futures_contract.oscript (L85-93)
```text
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
