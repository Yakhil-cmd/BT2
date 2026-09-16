## Title
Data feed reads in oscript/AA execution have no built-in staleness/freshness enforcement, allowing AAs to silently consume arbitrarily outdated oracle values - ([File: data_feeds.js])

### Summary
The external report flags a bug class where oracle-consuming contracts fail to enforce a maximum allowed staleness (`maxDelayTime`) for price data, letting stale prices be silently accepted. The analogous condition exists in `ocore`'s `data_feed` primitive used by Autonomous Agents (AAs): the protocol provides no default or enforced "max age" for a data feed value. The `timestamp` parameter that is threaded through `readDataFeedValue` is never actually used to bound freshness, and the `min_mci` filter defaults to `0`, meaning any AA that queries `data_feed[[oracles=..., feed_name=...]]` without explicitly adding its own staleness guard will accept whatever value the oracle posted last — no matter how long ago — exactly mirroring the reported bug (a freshness bound that exists in name/interface but is not enforced).

### Finding Description
`data_feed` values are read via `readDataFeedValueByParams` → `readDataFeedValue` → `readDataFeedByAddress`/`readDataFeedValue`'s unstable-message scan. The function signature explicitly accepts a `timestamp` argument: [1](#0-0) 

but that parameter is never referenced anywhere inside `readDataFeedValue`'s body, `readDataFeedByAddress`, or the unstable-candidate scanning loop — it is dead code with respect to freshness enforcement: [2](#0-1) [3](#0-2) 

The only bound available to a caller is `min_mci`, which the oscript evaluator (`formula/evaluation.js`, case `'data_feed'`) defaults to `0` unless the AA author explicitly supplies it: [4](#0-3) 

and `readDataFeedByAddress` will happily return the newest value found in the `[min_mci, max_mci]` window, with `min_mci=0` meaning "any historical value is acceptable": [5](#0-4) 

There is no protocol-level concept analogous to `maxDelayTime`/heartbeat — no mechanism compares the current MCI/timestamp against the feed's posting time and rejects it if too old. Freshness protection is entirely opt-in and must be hand-rolled by the AA author (e.g., by comparing `timestamp` against the feed unit's timestamp separately, which existing sample AAs do inconsistently). The bundled sample contracts illustrate this reliance on manual, easily-omitted checks, e.g. `futures_contract.oscript` uses a hard-coded maturity date rather than any oracle staleness check when consuming `data_feed[[...]]` for pricing: [6](#0-5) [7](#0-6) 

Because the platform exposes no default/enforced staleness parameter, any AA author who forgets to add an explicit "is this feed recent enough" check (analogous to forgetting to initialize `maxDelayTime`) will have their AA operate on outdated data indefinitely, with no framework-level fallback.

### Impact Explanation
AAs that use `data_feed` to price assets, settle bets/options/futures, or gate fund transfers (as in the bundled `futures_contract.oscript`/`option_contract.oscript` patterns) can be triggered with a stale price if the oracle stops posting updates (outage, compromise, network partition) or is slow. Because the primitive returns "the latest known value" with no age bound by default, an attacker (any unprivileged AA trigger sender) can time a trigger to exploit a known-stale price, causing incorrect settlement, asset issuance at a wrong rate, or fund loss/freezing in the AA — matching the "AA fund loss" impact class in scope.

### Likelihood Explanation
Likelihood is driven by AA-author error rather than a low-level protocol defect: any AA that calls `data_feed[[...]]` without independently cross-checking recency (e.g., comparing `timestamp` to the feed-posting MCI, which is not automatically available/enforced) is exposed. Given that the `timestamp` parameter exists in the API surface but is unused, and `min_mci` defaults to `0`, it is easy for an AA author to believe some staleness protection exists and omit their own, especially in complex financial AAs referencing sample templates in this repo.

### Recommendation
Provide (or strongly surface) an explicit, enforced staleness mechanism for `data_feed` reads:
- Add a documented `max_age`/`max_delay` parameter to `data_feed[[...]]` in `formula/evaluation.js` and `data_feeds.js` that compares the feed-posting unit's timestamp/MCI against `objValidationState.last_ball_timestamp`/current MCI and fails (or falls back to `ifnone`) when exceeded, rather than leaving the unused `timestamp` argument as dead code.
- Update oscript validation (`formula/validation.js`'s `validateDataFeed`) to require or default such a parameter, and update documentation/sample contracts (`futures_contract.oscript`, `option_contract.oscript`) to demonstrate the safe pattern, consistent with the Pyth/API3/Chainlink best-practice guidance referenced in the source report.

### Proof of Concept
1. An AA is deployed that reads `data_feed[[oracles='ORACLE_ADDR', feed_name='PRICE']]` without a `min_mci`/manual timestamp check, using it directly to compute a payout (as in the bundled `option_contract.oscript`/`futures_contract.oscript` samples).
2. The oracle at `ORACLE_ADDR` posts a price and then stops posting for an extended period (goes offline, is compromised, or simply has infrequent updates).
3. `readDataFeedValueByParams`/`readDataFeedValue` in `data_feeds.js` will still return that old value as the "current" price because `min_mci` defaults to `0` and the `timestamp` argument passed in is never checked against feed freshness (`data_feeds.js` lines 204-329).
4. Any unprivileged user posts a trigger unit to the AA at a moment favorable to the stale price, causing the AA to settle/pay out based on outdated market data — the same outcome the original report describes for `API3Oracle`/`ChainlinkOracle`/`PythOracle` consumers lacking a working `maxDelayTime` check.

### Citations

**File:** data_feeds.js (L204-205)
```javascript
// timestamp is for light only
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
```

**File:** data_feeds.js (L211-285)
```javascript
	if (bIncludeUnstableAAs) {
		var arrCandidates = [];
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.sequence !== 'good')
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
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
		}
		if (arrCandidates.length === 1) {
			var feed = arrCandidates[0];
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			if (ifseveral === 'last')
				return handleResult(objResult);
		}
		else if (arrCandidates.length > 1) {
			if (ifseveral === 'abort') {
				objResult.bAbortedBecauseOfSeveral = true;
				return handleResult(objResult);
			}
			arrCandidates.sort(function (a, b) {
				if (a.latest_included_mc_index < b.latest_included_mc_index)
					return -1;
				if (a.latest_included_mc_index > b.latest_included_mc_index)
					return 1;
				if (a.level < b.level)
					return -1;
				if (a.level > b.level)
					return 1;
				if (bIncludeAllUnstable) // still ambiguous, sort randomly (it's OK outside AAs)
					return 1;
				throw Error("can't sort candidates "+a+" and "+b);
			});
			var feed = arrCandidates[arrCandidates.length - 1];
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			return handleResult(objResult);
		}
	}
	async.eachSeries(
		arrAddresses,
		function(address, cb){
			readDataFeedByAddress(address, feed_name, value, min_mci, max_mci, ifseveral, objResult, cb);
		},
		function(err){ // err passed here if aborted because of several
			console.log('data feed by '+arrAddresses+' '+feed_name+', val='+value+': '+objResult.value+', dfv took '+(Date.now()-start_time)+'ms');
			handleResult(objResult);
		}
	);
}
```

**File:** data_feeds.js (L287-339)
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
	kvstore.createReadStream(options)
	.on('data', handleData)
	.on('end', function(){
		handleResult(objResult.bAbortedBecauseOfSeveral);
	})
	.on('error', function(error){
		throw Error('error from data stream: '+error);
	});
}
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

**File:** test/samples/futures_contract.oscript (L59-90)
```text
			{ // record blackswan event
				if: `{ trigger.data.blackswan AND !var['blackswan'] AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA']] < 25 AND timestamp < 1556668800 }`,
				messages: [{
					app: 'state',
					state: `{
						var['blackswan'] = 1;
						response['blackswan'] = 1;
					}`
				}]
			},
			// 1 GB is now 50 USD, 1 byte is 50e-9 = 5e-8 USD
			// 1 usd asset is always 2.5e-8 USD, 1 gb asset is 1 byte minus 2.5e-8 USD
			{ // pay bytes in exchange for the assets
				if: `{
					if (trigger.output[[asset!=base]].asset == 'none')
						return false;
					$gb_asset_amount = trigger.output[[asset=var['gb_asset']]];
					$usd_asset_amount = trigger.output[[asset=var['usd_asset']]];
					if ($gb_asset_amount < 1e4 AND $usd_asset_amount < 1e4)
						return false;
					if ($gb_asset_amount == $usd_asset_amount){ // helps in case the exchange rate is never posted
						$bytes = $gb_asset_amount;
						return true;
					}
					if (var['blackswan'])
						$bytes = $usd_asset_amount;
					else{
						if (timestamp < 1556668800)
							bounce('wait for maturity date');
						// data_feed will abort if the exchange rate not posted yet
						$exchange_rate = data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']];
						$bytes_per_usd_asset = min(50/$exchange_rate/2, 1);
```

**File:** test/samples/option_contract.oscript (L59-73)
```text
			{ // record the outcome
				if: `{(trigger.data.winner == 'yes' OR trigger.data.winner == 'no') AND !var['winner']}`,
				messages: [{
					app: 'state',
					state: `{
						if (trigger.data.winner == 'yes' AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD']] > 60)
							var['winner'] = 'yes';
						else if (trigger.data.winner == 'no' AND timestamp > 1556668800)
							var['winner'] = 'no';
						else
							bounce('suggested outcome not confirmed');
						response['winner'] = trigger.data.winner;
					}`
				}]
			},
```
