### Title
AA response formulas can consume not-yet-stabilized oracle price updates, enabling a sandwich attack on price-dependent Autonomous Agents - (File: `formula/evaluation.js`, `data_feeds.js`)

### Summary
Autonomous Agents (AAs) that price assets/exchange rates using `data_feed[[...]]` (e.g. the GBYTE/USD exchange‑rate pattern shown in `test/ojson.test.js`) read oracle values through `dataFeeds.readDataFeedValue()`, which, when invoked from AA formula evaluation, explicitly includes **unstable** (not-yet-finalized) data‑feed messages posted by the oracle, not only stable/confirmed ones. This lets an attacker who is watching the oracle's pending price-update unit propagate through the DAG craft two of his own AA-trigger units — one deliberately excluding the pending oracle unit from its ancestry (old price) and one deliberately including it (new price) — to sandwich the price update and extract risk-free profit from the AA, exactly analogous to the reported Custom Oracle `setPrices()`/`getPriceInEth()` sandwich.

### Finding Description
When a formula evaluates `data_feed[[oracles=..., feed_name=...]]` inside an AA response, it calls: [1](#0-0) 

`dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, ...)`

Here `bAA` (true while evaluating inside an AA) is passed as the `unstable_opts` argument. Inside `readDataFeedValue`, this flag turns on a code path that scans `storage.assocUnstableMessages` — i.e., messages from units that are **not yet stable** — and accepts a `data_feed` message from the oracle as a valid value as long as the message's containing unit's `latest_included_mc_index` falls within `[min_mci, max_mci]` and the oracle address is among the unit's `author_addresses`: [2](#0-1) 

Because inclusion is judged purely by DAG ancestry (`latest_included_mc_index`) rather than by whether the price-update unit is finalized, whichever unstable oracle unit an AA-trigger unit "sees" through its parent set is what gets used to price the trade. A user constructing a trigger unit fully controls which parent units (and therefore which included ancestors) it references before broadcasting.

An attacker monitoring the network can observe the oracle's price-update unit as soon as it is broadcast (well before it stabilizes), and:
1. Immediately compose and broadcast a trigger unit `A` (e.g., "buy" leg of the priced AA) whose parents deliberately do **not** include the oracle's new unit, so `readDataFeedValue` still resolves to the old (stale, more favorable) price.
2. Once the oracle's unit is visible in the DAG (still possibly unstable), compose and broadcast a second trigger unit `B` (e.g., the "sell"/redeem leg) whose parents **do** include the oracle's unit as an ancestor, so it resolves to the new price.

Both `A` and `B` can be accepted, validated, and eventually processed by the AA engine (`aa_composer.js`'s `handleAATriggers`, which processes triggers in `mci, level, unit` order once each trigger's containing unit stabilizes) using the price the attacker chose, producing a deterministic arbitrage profit against the AA's asset/byte reserves.

### Impact Explanation
Any AA that determines a price/exchange rate via `data_feed`/`in_data_feed` — the intended and documented usage pattern in Obyte, exactly as illustrated by the exchange-rate AA in `test/ojson.test.js` (lines 1049-1074, using `data_feed[[..., feed_name='GBYTE_USD_MA_2019_04_30']]` to compute `$bytes_per_usd_asset`) — is exposed to guaranteed-profit sandwiching around every oracle price update. This causes direct fund loss from the AA's bytes/asset reserves to the attacker, i.e., unauthorized value extraction/AA fund loss, each time the oracle posts a new price.

### Likelihood Explanation
The precondition set is fully attacker-reachable: an ordinary user can post arbitrary payment/trigger units addressed to a public AA (no special role required), can choose their own unit's parents, and can observe oracle price-update units as soon as they propagate on the network but before they stabilize. No hub, node, or oracle compromise is needed — only a live price-sensitive AA and a normal oracle price update, both of which are core, expected use cases of the platform's `data_feed` primitive.

### Recommendation
- For AA responses, do not resolve `data_feed` against unstable oracle messages by default; require the referenced data-feed unit to be stable (or introduce an explicit, opt-in "allow unstable" parameter with strong warnings), removing the `bIncludeUnstableAAs` unstable-message scan path in `data_feeds.js` (lines 211-274) from the default AA evaluation path in `formula/evaluation.js`.
- Alternatively, document and encourage AA authors to add a cooldown/commit-reveal or TWAP-style averaging (already partially mirrored by `GBYTE_USD_MA` moving-average feeds) so that a single not-yet-stable price post cannot be selectively included/excluded by trigger senders to guarantee arbitrage.

### Proof of Concept
1. Oracle broadcasts unit `U` with `data_feed` message updating `feed_name` to a materially different price; `U` propagates to full nodes but is not yet stable.
2. Attacker composes trigger unit `A` to the price-dependent AA with parents chosen so that `U` is not an ancestor; broadcasts it. `readDataFeedValue` (via the `bIncludeUnstableAAs` branch, `data_feeds.js:211-240`) resolves to the pre-update price when `A`'s trigger is processed.
3. Once `U` is visible in the DAG, attacker composes trigger unit `B` with parents that include `U` as ancestor; broadcasts it. On processing, `readDataFeedValue` now resolves the new price because `U`'s `latest_included_mc_index` falls within `B`'s `[min_mci, max_mci]` window.
4. Depending on which leg (buy low, then sell/redeem high) the AA logic exposes, the attacker nets a profit funded by the AA's reserve, replicating the sandwich pattern described in the source report against `CustomSetOracle.setPrices()`/`getPriceInEth()`.

### Citations

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** data_feeds.js (L211-240)
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
```
