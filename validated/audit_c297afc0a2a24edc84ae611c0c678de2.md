### Title
AA-level data feed freshness relies on immutable, MCI-based `min_mci`/`max_mci` bounds instead of real time or elapsed volatility, mirroring TWAP's inflexible fixed update period - (File: `data_feeds.js`, `formula/evaluation.js`)

### Summary
The referenced Vader finding concerns a TWAP oracle whose `_updatePeriod` is a single, immutable value set at deployment and shared across all assets, ignoring each asset's volatility and thereby risking stale or manipulable pricing. The analogous mechanism in ocore is the `data_feed[[...]]` oscript function and its underlying implementation, which let an AA author gate on oracle freshness only via `min_mci` (and implicitly `max_mci = mci`), a main-chain-index count rather than a real elapsed-time or volatility-aware window. Because AA `base` definitions (including any hardcoded `min_mci` thresholds baked into an AA's oscript) are immutable once deployed, and because MCI progression speed is not fixed relative to wall-clock time, this "freshness parameter" suffers from exactly the same class of rigidity the report criticizes in `TwapOracle.sol`: a single fixed threshold, chosen once, that cannot be tuned per asset risk profile or adapted post-deployment.

### Finding Description
The oscript `data_feed` function is evaluated in `formula/evaluation.js`, where the only recency control exposed to the AA author is `min_mci` (defaulting to `0`), which is passed straight into `dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, ...)`. [1](#0-0) [2](#0-1) 

The actual lookup in `data_feeds.js` scans keys bounded strictly by `min_mci`/`max_mci` (an MCI range), and simply returns the newest matching value within that window with no independent concept of real elapsed time or volatility-scaled freshness: [3](#0-2) [4](#0-3) 

The `formula/validation.js` validator for `data_feed` params only checks that `min_mci` is a non-negative integer string — it does not, and structurally cannot, encode a "maximum age" or "minimum required freshness" concept, nor does it allow different assets referenced within the same AA to have different tunable staleness tolerances beyond what the author manually hardcodes: [5](#0-4) 

Because AAs are immutable after being defined (their `base` oscript logic, including any hardcoded `min_mci` offset or absence of a timestamp check, cannot be upgraded), any `min_mci` value chosen at deployment time is permanently fixed — precisely the "inflexible `_updatePeriod`" problem from the report, just expressed in MCI units instead of a Solidity `_updatePeriod`. The sample AAs in the repository confirm this pattern is expected to be handled entirely ad hoc by the AA author using `timestamp` comparisons rather than any protocol-provided volatility-aware mechanism, e.g. `futures_contract.oscript` manually gates on `timestamp < 1556668800` around its `data_feed[[...]]` call, with a comment noting "data_feed will abort if the exchange rate not posted yet" — but nothing prevents the AA from using an arbitrarily old value that is still the "last" one within the MCI window if the author omits or miscalibrates such a check: [6](#0-5) 

Additionally, MCI advancement rate is not fixed relative to wall-clock time (main chain index growth depends on network unit production rate), so a single, fixed `min_mci` offset chosen for one asset's expected volatility does not scale correctly to other assets or to periods of variable network activity — the same "one size does not fit all assets/conditions" critique leveled at Vader's shared `_updatePeriod`.

### Impact Explanation
An AA author who (a) hardcodes a single `min_mci` threshold intended to bound data-feed staleness across multiple assets of differing volatility, or (b) relies on `min_mci` alone (block-count-based) rather than a real-time bound, can end up accepting price/data-feed values that are effectively far more stale in wall-clock terms during periods of slow main-chain growth, or unnecessarily rejecting fresh values during periods of fast growth. Since AA logic is immutable post-deployment, this miscalibration cannot be corrected without redeploying the AA, and any financial logic (asset issuance ratios, collateral valuation, swap pricing) gated on such feeds is exposed to inconsistent freshness guarantees, enabling mispriced issuance/transfer of AA-controlled funds if an attacker times a payment trigger during a period when the effective real-time staleness bound is looser than intended.

### Likelihood Explanation
Likelihood is moderate: it requires an AA author to rely solely on MCI-based bounds (the only protocol-native option) without additionally hardcoding a manual `timestamp` check (as the sample AA does), and it requires variability in main-chain unit production rate to create a meaningful mismatch between intended and actual staleness windows. Because MCI-based freshness is the default, protocol-endorsed mechanism exposed by `data_feed[[...]]`, and no built-in "age" or "elapsed time since last update" primitive tied to volatility exists, this class of miscalibration is plausible in real AA deployments that use data feeds for pricing.

### Recommendation
Provide a protocol-native, wall-clock-based freshness primitive for `data_feed[[...]]` reads (e.g., an optional `max_age` parameter validated against `objValidationState.last_ball_timestamp` rather than requiring AA authors to manually reconstruct timestamp checks), so that freshness bounds are expressed in real time and can be tuned independently per feed/asset instead of relying solely on a fixed MCI offset. Document clearly that `min_mci` alone does not guarantee a fixed real-time freshness bound, and encourage/require AA templates to combine `min_mci`/`max_mci` with explicit `timestamp` comparisons.

### Proof of Concept
1. Deploy an AA with a payment trigger gated by `data_feed[[oracles=..., feed_name='PRICE', min_mci=N]]` and no `timestamp` check, similar to the pattern in `test/samples/futures_contract.oscript` lines 59-90 but omitting the `timestamp < ...` guard. [7](#0-6) 
2. During a period of slow main-chain progression, the oracle's last posted price (posted many real-time hours/days ago) still satisfies `min_mci=N` because few MC indices have elapsed, even though the price is stale in wall-clock terms.
3. `readDataFeedValue`/`readDataFeedByAddress` in `data_feeds.js` returns this stale value as the "last" candidate within the MCI window without any independent recency check. [3](#0-2) 
4. The AA executes its payment logic using the stale price, resulting in mispriced issuance/transfer of AA-held funds.

### Citations

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

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

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

**File:** data_feeds.js (L287-311)
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
```

**File:** formula/validation.js (L55-60)
```javascript
				case 'min_mci':
					if (!(/^\d+$/.test(value) && ValidationUtils.isNonnegativeInteger(parseInt(value)))) return {
						error: 'bad min_mci',
						complexity
					};
					break;
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
