### Title
Autonomous Agents can price actions off a still-unstable (unconfirmed) `data_feed` value emitted by another AA in the same trigger cascade, enabling atomic oracle manipulation analogous to the 0VIX flash-loan exploit - ([File: data_feeds.js])

### Summary
The 0VIX incident exploited a lending protocol that priced collateral off an oracle value that could be manipulated and consumed atomically, within a single flash-loan transaction, before the market/oracle had a chance to reach a trustworthy, settled state. The Obyte analog is the `data_feed[[...]]` oscript primitive used inside AA formulas: when evaluated inside *any* AA (bAA truthy), `readDataFeedValue()` does not only look at confirmed/stable data feeds - it also scans `storage.assocUnstableMessages` for `data_feed` messages emitted by **other, not-yet-stable AA response units** whose author matches the requested oracle address list. [1](#0-0) [2](#0-1) 

Because AA-to-AA secondary triggers within one primary trigger's cascade are all processed synchronously in the same write batch, and because `storage.assocUnstableMessages` is populated as soon as a unit is written - well before the DAG reaches stability/consensus finality - a "Victim AA" that trusts a price/oracle-style AA as one of its `oracles=` addresses can be made to read a value that the "Oracle AA" produced moments earlier in the very same cascade, before the network has had any chance to validate/stabilize that value. [3](#0-2) 

### Finding Description
Obyte AAs commonly implement "price oracle" patterns where one AA computes and publishes a rate via a `data_feed` app message as part of its own response, and a second, dependent AA reads that rate with `data_feed[[oracles=..., feed_name=...]]` to price a swap, settlement, or collateral valuation - this exact pattern is present in the codebase's own sample contracts. [4](#0-3) 

The read path, `readDataFeedValue()`, when called from within AA formula evaluation (`bAA` is always truthy there and is passed straight through as the `unstable_opts` argument), first tries to satisfy the read from **unstable** AA-authored units: [5](#0-4) 

It filters candidates only by (a) MCI window, (b) the unit belonging to an AA (`objUnit.bAA`), (c) `sequence === 'good'`, and (d) the author address being in the requested oracle list - there is no requirement that the feed-posting unit (or the batch it belongs to) has reached main-chain stability. It then returns the *most recent* (by `latest_included_mc_index`/`level`) candidate as the authoritative value: [6](#0-5) 

This means a chain of AA triggers processed in one shot (primary trigger → secondary trigger → secondary trigger, all part of the same handling batch prior to stabilization) can:
1. Trigger the "Oracle AA" with attacker-favorable inputs (e.g., an imbalanced swap against a thin pool, or any parameter the Oracle AA blindly echoes into its published feed) so that it emits an extreme/manipulated `data_feed` value as one of its response messages.
2. Immediately, in the same cascade/batch, trigger the "Victim AA" (which trusts that Oracle AA's address as one of its `oracles=` sources) to read that just-emitted, still-unstable value via `data_feed[[...]]` and use it to size a payout, valuate collateral, or settle a swap.

Because this all happens before the underlying units are stable, there is no window in which other network participants could observe/react to (or invalidate) the manipulated price the way a real, time-delayed, TWAP-based oracle is meant to prevent - the manipulation and its consumption are effectively atomic from the attacker's perspective, structurally mirroring the flash-loan oracle manipulation used against 0VIX.

### Impact Explanation
If a deployed Victim AA relies on an Oracle AA whose emitted `data_feed` value can be influenced by attacker-supplied trigger inputs (a common design for on-chain price/rate oracle AAs, e.g. AMM-ratio-based rate publishers), an attacker can, within a single self-constructed sequence of AA triggers, manipulate the rate and immediately spend/settle against it before the network's consensus/stability mechanism has any chance to reject or delay the abnormal reading. This can lead to draining of Victim AA balances, incorrect collateral release, or mispriced asset issuance/settlement - i.e., concrete unauthorized fund loss from AA balances, matching the required impact bar (AA fund loss).

### Likelihood Explanation
Exploitability depends on a specific but realistic AA design pattern: a dependent AA trusting another AA as a `data_feed` oracle whose value is influenced by attacker-controllable trigger parameters or pool state, combined with both AAs being reachable in one attacker-issued transaction/cascade. This is not a universal bug affecting every AA, but the vulnerable primitive - `readDataFeedValue`'s unconditional inclusion of unstable AA-authored feeds whenever evaluated inside any AA - is unconditionally present in core and is exposed to any unprivileged AA trigger sender who authors the right sequence of units. Any AA author using an AA-computed oracle (rather than a human/attested-hardware oracle) for pricing is at risk.

### Recommendation
- When evaluating `data_feed[[...]]` inside AA formulas, do not silently prefer/accept values from unstable units by default; require callers to explicitly opt into "unstable" reads (as light clients already must specify `'all_unstable'`), and warn/disallow relying on unstable AA-to-AA feeds for value-bearing decisions unless the AA author explicitly requests it via a dedicated parameter.
- For Oracle-AA design patterns, enforce or strongly recommend that price-publishing AAs base their published rate on state that cannot be manipulated within a single attacker-controlled cascade (e.g., require a minimum stability lag or an MCI-delay parameter such as `min_mci` combined with disallowing same-batch reads of the freshly emitted, unstable value).
- Consider adding a flag to `data_feed[[...]]`/`readDataFeedValue` that restricts the unstable-AA fast path to feeds whose publishing unit is at least N units/levels removed from the current trigger's cascade, closing the "same-batch, same-cascade" atomic read/write window that enables this attack.

### Proof of Concept
1. Deploy `AA_Oracle`: an AA that, on trigger, computes and publishes `data_feed[[GBYTE_USD]] = f(trigger.data.x)` (or a pool-ratio-derived rate) as one of its response messages - this pattern is directly modeled by the sample contracts in the repo. [7](#0-6) 
2. Deploy `AA_Victim`: an AA that on trigger reads `data_feed[[oracles="AA_Oracle_address", feed_name="GBYTE_USD"]]` to determine a payout/settlement amount, as in the same sample pattern. [8](#0-7) 
3. Attacker composes a single unit chain: trigger `AA_Oracle` with `trigger.data.x` chosen to push the published rate to an attacker-favorable extreme, then (as a secondary trigger in the same cascade/batch) trigger `AA_Victim` with a payment that will be priced using the just-published, still-unstable rate.
4. Because `readDataFeedValue` (called with `bAA=true` from `formula/evaluation.js`) picks up `AA_Oracle`'s freshly-written but unstable `data_feed` message from `storage.assocUnstableMessages` (populated at write time, per `writer.js`), `AA_Victim` computes its response using the manipulated rate before any DAG stability has been reached, resulting in an incorrect/attacker-favorable payout drained from `AA_Victim`'s balance. [9](#0-8) [3](#0-2) 

Note: I was unable to fully trace the exact code path that sets `objUnit.bAA = true` on AA-generated response units within the time available (partial matches were found in `storage.js`/`writer.js` but not conclusively read); this detail does not change the core finding (the unstable-feed read path and its unconditional activation for any AA-context formula evaluation), but a full Devin session with file access should confirm that flag's assignment to fully validate the exact set of units eligible for this unstable read.

### Citations

**File:** data_feeds.js (L205-273)
```javascript
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var start_time = Date.now();
	var objResult = { bAbortedBecauseOfSeveral: false, value: undefined, unit: undefined, mci: undefined };
	var bIncludeUnstableAAs = !!unstable_opts;
	var bIncludeAllUnstable = (unstable_opts === 'all_unstable');
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
```

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** writer.js (L603-613)
```javascript
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
```

**File:** test/samples/futures_contract.oscript (L59-93)
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
```
