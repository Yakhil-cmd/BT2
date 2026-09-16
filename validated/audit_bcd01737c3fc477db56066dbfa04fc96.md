### Title
Race condition in `data_feed`/`in_data_feed` oracle-threshold evaluation lets an AA finalize an outcome before a legitimately-posted but not-yet-stable price update is counted, permanently locking in the wrong side's payout - ([File: ocore--010/formula/evaluation.js], [File: ocore--010/data_feeds.js])

### Summary
The Sherlock report describes a "proof of depeg" timing gap: a price crossing a threshold is real and later provable on-chain, but if the triggering transaction is not settled before the epoch/condition window closes, the protocol resolves as if the depeg never happened, causing the side that should have won to lose its funds. Obyte AAs implement the exact analogous pattern with oracle price thresholds evaluated through `data_feed[[...]]` / `in_data_feed[[...]]` in oscript, as used by the `option_contract.oscript` and `futures_contract.oscript` samples to decide a binary winner/blackswan outcome based on whether an oracle posted a qualifying value before a given point.

### Finding Description
`data_feed` evaluation resolves to `dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, ...)` [1](#0-0)  and `in_data_feed` resolves to `dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb)` [2](#0-1) . Both functions only "see" a data feed unit if that unit's `latest_included_mc_index` (and, for the non-AA-unstable branch, its stability) falls within `[min_mci, max_mci]` at the moment the AA trigger unit itself is evaluated [3](#0-2) [4](#0-3) .

This is functionally identical to `triggerDepeg()`: the oracle (equivalent of the price-monitoring keeper) posts a `data_feed` unit reporting the qualifying price, but that unit must be included/stable relative to the AA-triggering unit's MCI window to be counted. Sample contracts explicitly rely on this race: the outcome branch checks
```
if (trigger.data.winner == 'yes' AND data_feed[[oracles='X55...', feed_name='GBYTE_USD']] > 60)
    var['winner'] = 'yes';
else if (trigger.data.winner == 'no' AND timestamp > 1556668800)
    var['winner'] = 'no';
else
    bounce('suggested outcome not confirmed');
``` [5](#0-4)  and the blackswan branch:
```
if: `{ trigger.data.blackswan AND !var['blackswan'] AND data_feed[[oracles='X55...', feed_name='GBYTE_USD_MA']] < 25 AND timestamp < 1556668800 }`
``` [6](#0-5) .

If the oracle price crosses the threshold near the resolution deadline (or near the trigger's MCI), but the corresponding `data_feed` unit has not yet reached the required `latest_included_mc_index`/stability at the time some user's trigger is processed, `readDataFeedValue`/`dataFeedExists` will not find it, so the "depeg"/blackswan/winner condition silently evaluates as false. The AA then either bounces or resolves the state variable (`var['winner']`, `var['blackswan']`) to the wrong, permanent value, because these are one-shot guarded by `!var['winner']` / `!var['blackswan']`. There is no on-chain mechanism to submit or validate a later "proof" that the price crossed the threshold in time — once the state variable is set (or the deadline `timestamp` passes and locks in the alternate branch), the outcome is final and irreversible, exactly mirroring the report's "lack of proof of depeg" issue.

### Impact Explanation
Because outcome-state variables (`var['winner']`, `var['blackswan']`) are set exactly once and gate subsequent payment branches such as
```
{ // pay bytes in exchange for the assets ... if (var['blackswan']) $bytes = $usd_asset_amount; else { ... $exchange_rate = data_feed[[...]]; ... } }
``` [7](#0-6) , an unprivileged trigger sender's timing relative to the oracle's unit propagation/stabilization determines which side of a two-sided position (analogous to the "premium" vs "collateral" vault) receives funds. A legitimate real-world price event that occurred but whose oracle attestation unit had not yet met the MCI/stability window used by `readDataFeedValue`/`dataFeedExists` at the moment a trigger is processed will cause the AA to permanently lock in the outcome that favors the wrong party, resulting in unauthorized/incorrect fund distribution (one side losing assets it should have won) with no recourse.

### Likelihood Explanation
This requires no malicious actor — an oracle posting the qualifying `data_feed` value near the deadline, combined with normal unit stabilization delay, is sufficient to trigger the race. Any AA author who builds binary/threshold-outcome contracts using `data_feed`/`in_data_feed` guarded by one-shot state variables (as shown in the shipped sample templates `option_contract.oscript` and `futures_contract.oscript`) is exposed, and any unprivileged trigger sender can be the one who inadvertently (or opportunistically) submits the resolving trigger just before/after the oracle unit stabilizes, deciding the outcome.

### Recommendation
For AA templates that decide binary financial outcomes from a single oracle threshold check, add a dispute/grace mechanism analogous to the report's recommendation: allow a window where a subsequent, provably-earlier `data_feed` post can still flip the resolution before final payout is locked, or require the resolving trigger to reference/confirm the oracle unit's MCI is what was intended, and consider requiring the oracle to also post an explicit "epoch closed with value X" attestation rather than relying purely on presence/absence of a threshold-crossing message within an implicit MCI window at `data_feeds.js:205-284`/`data_feeds.js:13-108`. This is a contract-design-level mitigation since `data_feed`/`in_data_feed` themselves function as documented (present/absent within an MCI window), and the vulnerability lies in application logic that treats absence-within-window as proof of absence-of-event.

### Proof of Concept
1. Deploy an AA using the pattern from `test/samples/option_contract.oscript` (or `futures_contract.oscript`), with an outcome branch gated by `data_feed[[oracles=..., feed_name=...]] > threshold` and a one-shot state variable `var['winner']`/`var['blackswan']` [5](#0-4) .
2. Oracle observes the real price crossing the threshold and posts a `data_feed` unit reporting it, but the unit has not yet reached `latest_included_mc_index <= max_mci` relative to the pending resolving trigger unit (network propagation/stabilization delay), per the MCI-window check in `dataFeedExists`/`readDataFeedValue` [3](#0-2) .
3. Any user posts a trigger with `trigger.data.winner` set to the alternate outcome before the oracle's unit is counted; the AA's `data_feed[[...]] > threshold` check evaluates false (feed not yet visible in the required window), so the `else` branch fires and `var['winner']` is permanently set to the wrong side [8](#0-7) .
4. Subsequent redemption logic pays out based on the locked-in `var['winner']`/`var['blackswan']` value, causing the side that should have won (per the real, later-provable price data) to lose its funds, with no on-chain path to correct the resolution [9](#0-8) .

### Citations

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** formula/evaluation.js (L745-745)
```javascript
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
```

**File:** data_feeds.js (L34-43)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
```

**File:** data_feeds.js (L211-224)
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
```

**File:** test/samples/option_contract.oscript (L59-72)
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
```

**File:** test/samples/futures_contract.oscript (L59-68)
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
```

**File:** test/samples/futures_contract.oscript (L71-95)
```text
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
				}`,
```
