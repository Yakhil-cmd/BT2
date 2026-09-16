## Title
Sandwiching of data-feed price updates read by Autonomous Agents - (File: `data_feeds.js`, `formula/evaluation.js`)

### Summary
Autonomous Agents (AAs) that price trades, collateral, or payouts from oracle data feeds (`data_feed[[...]]`/`in_data_feed[[...]]`) are exposed to the same "sandwich a price update" pattern described in the external report. The root cause is that, when evaluated inside an AA (`bAA` = true), a data-feed read is allowed to pick up an **unstable** (not-yet-finalized) oracle post that is merely in the right MCI window and authored by the right address — it does not require the AA trigger to be a DAG descendant of that oracle post. Because unstable units are gossiped to the network (and to light/full nodes) before they are finalized, an attacker who observes a pending price-update unit from a known oracle can race to submit a trigger unit that lands either just before or just after that update is picked up, extracting value from any AA that relies on that feed for swap/settlement pricing (AMMs, options, futures-style contracts).

### Finding Description
`data_feed[[...]]` inside oscript is evaluated by `getDataFeed()` in `formula/evaluation.js`, which calls `dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, ...)` with `bAA` set whenever the formula runs inside an AA response. [1](#0-0) 

`readDataFeedValue()` in `data_feeds.js` special-cases `bIncludeUnstableAAs` (driven by `bAA`): it scans `storage.assocUnstableMessages`, the node's in-memory table of messages from units that are **not yet stable**, and accepts any `data_feed` message whose author is in the oracle list and whose `latest_included_mc_index` falls in `[min_mci, max_mci]` — with no check that the AA-trigger unit is a causal descendant of the oracle's unit: [2](#0-1) 

The same unstable-scan pattern exists in `dataFeedExists()` (used by `in_data_feed[[...]]`), again gated only by `bAA` and MCI range, not DAG ancestry: [3](#0-2) 

Values only become permanently indexed (`df`/`dfv` keys) once the posting unit's MCI is marked stable, in `addDataFeeds()` invoked from `markMcIndexStable()`: [4](#0-3) 

Because unstable units are broadcast and visible to all peers well before their MCI stabilizes, an oracle's price-update unit is public knowledge for a window of time before it is authoritative. An unprivileged party who is watching the DAG can:
1. Detect the not-yet-stable price-update unit from the oracle the target AA trusts.
2. Immediately compose and broadcast a trigger unit to the AA (e.g., an AMM in `test/samples/uniswap_like_market_maker.oscript` or an option/futures-style contract in `test/samples/option_contract.oscript` / `test/samples/futures_contract.oscript`, all of which price payouts directly from `data_feed[[...]]`) timed to be processed with the *old* stable price, then submit a second trigger to be processed once the *new* value has propagated/stabilized, extracting the price differential from the AA/counterparties — the classic buy-low/sell-high sandwich, but built around the propagation-to-stabilization gap of a DAG-based data feed rather than a mempool.

Representative price-dependent AAs: [5](#0-4) [6](#0-5) [7](#0-6) 

### Impact Explanation
Any AA that trusts a data feed for pricing (swap rate, collateral value, settlement outcome) can have value extracted from it or from counterparties transacting around a price update, because the value that becomes authoritative can be "seen" and reacted to before it is final. This is a fund-loss vector for AA counterparties and reduces the reliability of price-dependent AA templates shipped as reference designs in this repository (AMM, options, futures samples), matching the Medium-severity impact class of the original report (loss of funds due to predictable/racable price updates).

### Likelihood Explanation
Likelihood is moderate: it requires (a) an oracle actively updating a feed used by a price-sensitive AA, (b) network-level visibility of the oracle's unstable unit before stabilization (a normal, expected condition of DAG propagation, not a privileged capability), and (c) the ability to submit ordinary trigger units, which any user can do. No special privileges, node compromise, or protocol violation are required — only ordinary use of `readDataFeedValue`'s documented unstable-read behavior (`bAA`/`unstable_opts`), so it is reachable by any unprivileged trigger sender who is timing their transactions around a known oracle's feed update.

### Recommendation
- For AAs that must be race-resistant, avoid keying critical settlement math off the most recent unstable oracle post; alternatively, extend the data-feed formula grammar/evaluation with an option to only accept *stable* values (i.e., skip the `bIncludeUnstableAAs` branch) for sensitive settlement paths, or require a minimum confirmation delay (`min_mci` several MCIs behind current) before a feed value can be used to settle trades.
- Document clearly, for AA authors, that `data_feed[[...]]` read from within an AA may reflect not-yet-stable oracle posts (per `readDataFeedValue`'s `bIncludeUnstableAAs` logic in `data_feeds.js`), and that this creates a sandwichable window; recommend AA templates add debounce/anti-sandwich mechanisms (e.g., TWAP over multiple stable posts, rate-limiting trigger frequency per address, or requiring the price age to exceed a threshold) rather than relying on the single latest value.

### Proof of Concept
1. Oracle O posts a new `data_feed` unit U1 updating `feed_name` used by AA `X` (e.g., `uniswap_like_market_maker.oscript`). U1 is broadcast to the network before its MCI is stable.
2. Attacker monitors the network, sees U1's payload before it stabilizes, and immediately posts trigger unit T1 to AA `X` designed to execute using the still-stale, previously-stable price (front-run), buying the underlying asset cheaply per `evaluate()`'s `data_feed` handling in `formula/evaluation.js:600-663`, which is resolved via `dataFeeds.readDataFeedValue` in `data_feeds.js:205-249`.
3. Once U1 and any concurrent legitimate user trigger T2 land within the same or adjacent MCI window, the attacker posts trigger T3 to AA `X` that will now pick up the *new* value (again via the `bIncludeUnstableAAs` branch, which returns the latest matching unstable candidate ranked by `latest_included_mc_index`/`level`) to sell back at the improved price, capturing the spread that would otherwise have accrued to the AA or the legitimate trader T2.
4. No special privileges are needed at any step — only knowledge of oracle O's address/feed name (public, embedded in the AA definition) and the ability to send ordinary payments/triggers to AA `X`.

### Citations

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

**File:** data_feeds.js (L13-44)
```javascript
function dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, max_mci, bAA, handleResult){
	var start_time = Date.now();
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	if (bAA) {
		var bFound = false;
		function relationSatisfied(v1, v2) {
			switch (relation) {
				case '<': return (v1 < v2);
				case '<=': return (v1 <= v2);
				case '>': return (v1 > v2);
				case '>=': return (v1 >= v2);
				default: throw Error("unknown relation: " + relation);
			}
		}
		function valueIsNumber() {
			if (typeof value === 'string') {
				const float = string_utils.toNumber(value, bLimitedPrecision);
				return float !== null;
			}
			return true;
		}
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
			storage.assocUnstableMessages[unit].forEach(function (message) {
```

**File:** data_feeds.js (L205-249)
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
```

**File:** main_chain.js (L1587-1617)
```javascript
								function addDataFeeds(payload){
									if (!storage.assocStableUnits[unit])
										throw Error("no stable unit "+unit);
									var arrAuthorAddresses = storage.assocStableUnits[unit].author_addresses;
									if (!arrAuthorAddresses)
										throw Error("no author addresses in "+unit);
									var strMci = string_utils.encodeMci(mci);
									for (var feed_name in payload){
										var value = payload[feed_name];
										var strValue = null;
										var numValue = null;
										if (typeof value === 'string'){
											strValue = value;
											var bLimitedPrecision = (mci < constants.aa2UpgradeMci);
											var float = string_utils.toNumber(value, bLimitedPrecision);
											if (float !== null)
												numValue = string_utils.encodeDoubleInLexicograpicOrder(float);
										}
										else
											numValue = string_utils.encodeDoubleInLexicograpicOrder(value);
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
									}
								}
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
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
