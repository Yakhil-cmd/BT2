### Title
AA trigger authors can select a stale `last_ball`/`last_ball_mci` to force AA formula evaluation (`data_feed`, `timestamp`, `mci`) to use outdated price/oracle data - ([File: formula/evaluation.js])

### Summary
The reported bug is about a caller-controlled execution timestamp (`_executableAtTime`) letting a user pick a `maxAge` that resolves to a stale, more favorable oracle price during settlement. In `ocore`, the analogous control point is the **AA trigger unit's own `last_ball_unit`**, which is chosen by the (unprivileged) unit poster/trigger author when composing their unit. This value determines `objValidationState.last_ball_mci` and `objValidationState.last_ball_timestamp`, which are the exact parameters fed into every `data_feed[[...]]`, `in_data_feed[[...]]`, `timestamp`, and `mci` evaluation inside the triggered AA's oscript formula.

### Finding Description
When an AA is triggered, `handleTrigger` builds the validation context directly from the trigger unit's declared last ball: [1](#0-0) 

During formula evaluation, both `data_feed`/`in_data_feed` lookups and `timestamp`/`mci` opcodes use this same `mci` (== `last_ball_mci`) and `last_ball_timestamp` as their reference point for "now": [2](#0-1) [3](#0-2) [4](#0-3) 

`readDataFeedValue`/`dataFeedExists` treat this `mci` as `max_mci`: they search *backward* from it for the most recent oracle post at or before that point, i.e. exactly the price/valuation "as of" the chosen `last_ball`: [5](#0-4) [6](#0-5) 

Critically, unit/parent validation does **not** require `last_ball_unit` to be the network's current tip or recent in any way. It only enforces internal monotonicity relative to the parents the author themselves chose: [7](#0-6) [8](#0-7) 

There is no check anywhere in `validateParents` bounding how far behind the current stable MC index `last_ball_mci` may be — only that it isn't lower than the max of whatever the author's own chosen parents already declared, and that it is consistent with those parents. An attacker composing a raw unit (bypassing the normal wallet composer, which by convention always picks the freshest free parents/last ball in `parent_composer.js`'s `pickParentUnitsAndLastBall`) can instead deliberately select older, valid, already-stable parent units and an older `last_ball_unit`. This is accepted by consensus validation as long as internal consistency rules (no same address across parents, non-retreating last-ball-mci, last ball included in parents) hold — none of which require freshness relative to "now".

The AA-oriented test fixtures (`futures_contract.oscript`, `option_contract.oscript`) show this exact price/oracle-and-timestamp-gated pattern is a real, expected use case for AAs in this codebase, confirming the reachable attack surface: [9](#0-8) [10](#0-9) 

### Impact Explanation
An AA trigger author who crafts a unit referencing an intentionally old `last_ball_unit` forces the entire AA formula evaluation (all `data_feed`, `in_data_feed`, `timestamp`, `mci` opcodes) to run against that stale point in time rather than the current stable state. For AAs that compute payout/exchange amounts from an oracle price feed (as in the sample futures/option contracts, and any real-world DeFi-style AA using `data_feed[[...]]` for pricing), this lets the trigger author pick a historically more favorable price instead of the current one, potentially extracting more funds than intended (AA fund loss) or bypassing `timestamp`-gated maturity/expiry checks by making the AA believe less time has passed than actually has. This mirrors the reported impact categories: unfair advantage, integrity risk, and gaming of price-dependent execution.

### Likelihood Explanation
Exploitation only requires the ability to author and broadcast a normal unit with hand-crafted `parent_units`/`last_ball_unit` fields (something any wallet-level unit poster can do without any special privilege), referencing older but still valid, already-stable ancestor units. No hub, witness, or node compromise is needed — this is purely a self-authored unit/trigger crafted by an ordinary user. The main constraint is that suitable old parent units must exist and be usable as parents (no cross-parent address conflicts), which is generally satisfiable since DAG parents are not required to be current "free" tips at validation time.

### Recommendation
- Enforce a maximum allowed staleness for `last_ball_mci`/`last_ball_timestamp` relative to the unit's own `timestamp` (or the network's current stable MC index) when the last ball is used to drive `data_feed`/`timestamp`/`mci` evaluation inside AA triggers, particularly rejecting or flagging triggers whose `last_ball` significantly lags behind the current tip.
- Alternatively/additionally, document and encourage AA authors to combine `data_feed` price reads with an explicit `min_mci`/freshness bound (already supported as a parameter) so that AAs relying on price feeds do not implicitly trust however-old a `last_ball` the trigger author supplied.
- Consider adding a core-level sanity check that rejects triggers whose `last_ball_mci` is more than N MCIs/seconds behind the best known stable MCI at receipt time (similar in spirit to the existing "timestamp is too far into the future" check), closing the "arbitrarily old last_ball" window while preserving the deterministic re-validation properties required by consensus.

### Proof of Concept
1. An attacker wants to trigger a price-dependent AA (e.g. one modeled on `test/samples/futures_contract.oscript`, using `data_feed[[oracles=..., feed_name='GBYTE_USD_MA']]`).
2. Instead of using the standard wallet composer (`parent_composer.pickParentUnitsAndLastBall`, which always selects the freshest free parents), the attacker manually crafts a unit whose `parent_units` and `last_ball`/`last_ball_unit` reference an older-but-valid, already-stable point in the DAG from a time when the oracle price was more favorable to them.
3. `validateParents` (`validation.js:668-741`) accepts this unit because it only checks internal, self-referential monotonicity ("last ball mci must not retreat" relative to the attacker's own chosen parents) — it never compares `last_ball_mci` to the network's actual current stable MCI.
4. When the trigger is processed, `handleTrigger` sets `objValidationState.last_ball_mci`/`last_ball_timestamp` from this stale `last_ball` (`aa_composer.js:450-453`).
5. The AA's `if`/`init`/`state` formulas evaluate `data_feed[[...]]` and `timestamp` against this stale context (`formula/evaluation.js:646`, `formula/validation.js:437-440`), causing `readDataFeedValue`/`dataFeedExists` to return the old, favorable price rather than the current one (`data_feeds.js:204-311`), letting the attacker settle/withdraw at a manipulated price or slip past a `timestamp`-gated maturity check.

### Citations

**File:** aa_composer.js (L450-453)
```javascript
	var objValidationState = {
		last_ball_mci: mci,
		last_ball_timestamp: objMcUnit.timestamp,
		mc_unit: objMcUnit.unit,
```

**File:** formula/evaluation.js (L600-610)
```javascript
			case 'data_feed':

				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
```

**File:** formula/evaluation.js (L646-656)
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
```

**File:** formula/validation.js (L437-440)
```javascript
			case 'mci':
			case 'timestamp':
				cb();
				break;
```

**File:** data_feeds.js (L204-208)
```javascript
// timestamp is for light only
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var start_time = Date.now();
	var objResult = { bAbortedBecauseOfSeveral: false, value: undefined, unit: undefined, mci: undefined };
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

**File:** validation.js (L668-674)
```javascript
	function readMaxParentLastBallMci(handleResult){
		storage.readMaxLastBallMci(conn, objUnit.parent_units, function(max_parent_last_ball_mci) {
			if (max_parent_last_ball_mci > objValidationState.last_ball_mci)
				return callback("last ball mci must not retreat, parents: "+objUnit.parent_units.join(', '));
			handleResult(max_parent_last_ball_mci);
		});
	}
```

**File:** validation.js (L737-741)
```javascript
					objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index;
					objValidationState.last_ball_timestamp = objLastBallUnitProps.timestamp;
					objValidationState.max_known_mci = objLastBallUnitProps.max_known_mci;
					if (objValidationState.max_parent_limci < objValidationState.last_ball_mci)
						return callback("last ball unit "+last_ball_unit+" is not included in parents, unit "+objUnit.unit);
```

**File:** test/samples/futures_contract.oscript (L59-94)
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
						$bytes_per_gb_asset = 1 - $bytes_per_usd_asset;
						$bytes = round($bytes_per_usd_asset * $usd_asset_amount + $bytes_per_gb_asset * $gb_asset_amount);
					}
					true
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
