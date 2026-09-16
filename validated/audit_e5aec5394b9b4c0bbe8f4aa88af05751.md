## Analysis

This maps directly onto Obyte's **Autonomous Agents (AAs)**. AAs support an "admin/oracle-controlled state variable" pattern that is explicitly documented and shipped in the codebase's own AA reference templates, e.g. `test/samples/sell_asset_for_bytes.oscript` and `test/samples/order_book_exchange.oscript`. In this pattern, a privileged address can post a trigger that updates a state variable (an exchange rate, a fee) at any time, and a *different, unprivileged* trigger later reads that variable to compute how much value to pay out — exactly the "owner sets fee to 100% before a pending user call executes" pattern from the Solidity report, translated to AA state and trigger evaluation order.

Trigger execution order in `ocore` is not FIFO by submission time — it is deterministic based on stabilization order: `main_chain.js` collects all trigger units for an MCI and orders them by `units.level, units.unit, address` [1](#0-0) , and `handleAATriggers` in `aa_composer.js` processes them in exactly `mci, level, unit, address` order [2](#0-1) . Because DAG level/parent selection is attacker-influenceable (an admin who observes a pending, not-yet-stable payment unit addressed to the AA can immediately compose and broadcast his own rate-change unit with fewer/earlier parents), the admin can guarantee his state-changing trigger is ordered and stabilized ahead of the victim's payment trigger within the same or an earlier MCI — a DAG-native analogue of mempool front-running.

## Title
Admin-controlled AA state variables (e.g. exchange rate/fee) can be front-run against pending user triggers, enabling unauthorized value extraction - (File: `aa_composer.js`, `main_chain.js`, AA template pattern in `test/samples/sell_asset_for_bytes.oscript`)

### Summary
Autonomous Agents that implement an "admin sets rate/fee, user later trades against that rate" pattern (as reference-shipped in `sell_asset_for_bytes.oscript` and `order_book_exchange.oscript`) read the current value of the admin-controlled state variable (`var['rate']`) at the time the trigger unit is *processed*, not at the time the user composed/sent it. Because AA triggers are executed in a deterministic DAG-stabilization order (`mci, level, unit, address`) rather than in submission order, and that order can be influenced by whoever races to get their unit onto a more favorable position in the DAG, the admin address can observe an incoming user payment unit before it stabilizes and post a rate/fee-changing trigger that gets ordered and executed first, extracting most or all of the user's payment value — directly analogous to the reported `setPrimarySaleFeeBps` front-run.

### Finding Description
- `handleTrigger` in `aa_composer.js` evaluates message formulas (e.g. `var['rate']`, `bounce_fees`) using the **current** state var values at execution time, and a payment message payout is calculated purely from that state at execution [3](#0-2) .
- The template samples shipped with the engine implement exactly this exploitable pattern: an admin (`$my_address`) trigger updates `var['rate']`, and any subsequent user trigger converts bytes to asset using whatever `var['rate']` happens to be at execution time, with no check that the rate matches what the user expected when they sent their payment [4](#0-3) .
- AA triggers are not processed in submission/broadcast order. They are collected per stabilized MCI and executed in a fixed deterministic order `ORDER BY units.level, units.unit, address` [5](#0-4) , and `handleAATriggers` iterates `aa_triggers` ordered by `mci, level, aa_triggers.unit, address` [2](#0-1) .
- Because unit `level` and DAG placement are influenceable by an author racing to get a lower level / earlier best-parent selection, the admin — after observing the victim's unpublished/unstable payment unit on the p2p network — can compose a rate-change unit that lands with an earlier `level` in the same or an earlier MCI, guaranteeing it is executed before the victim's exchange trigger.

### Impact Explanation
High. If it goes unnoticed, an admin/oracle address for an exchange-style AA can arbitrarily manipulate the effective exchange rate or fee immediately before a user's payment is processed, extracting nearly all of the user's sent value (asset or bytes) with no economic recourse for the victim, since the victim's funds are already locked into the AA's `outputs` computation once the trigger executes. This is a direct unauthorized-value-extraction scenario analogous to the "owner sets fee to 100%" rug described in the source report.

### Likelihood Explanation
Low-to-Medium. It requires a malicious or compromised AA-admin address (same precondition as the source report: a malicious/compromised privileged party), plus timing/network visibility of the pending user trigger unit before it stabilizes — both of which are realistic given that unconfirmed units are broadcast over Obyte's p2p network and DAG-level manipulation is achievable by any well-connected node.

### Recommendation
- AA templates that store admin-adjustable rates/fees should require the caller (`trigger.data`) to specify the expected rate/fee value, and `bounce()` if it doesn't match the currently stored `var[...]` value at execution time — mirroring the source report's recommendation to check the expected fee against the currently configured one and revert on mismatch.
- Where practical, cap how much an admin-controlled rate/fee can change per update (rate-limiting), or introduce a timelock/delay between an admin rate-change trigger and when it takes effect, so pending user triggers submitted before the change are guaranteed to use the pre-change rate.
- Document this footgun prominently in the official AA templates (`sell_asset_for_bytes.oscript`, `order_book_exchange.oscript`) since they are used as reference patterns by third-party AA developers who may copy the vulnerable design verbatim.

### Proof of Concept
1. Deploy an AA based on `sell_asset_for_bytes.oscript`'s pattern: admin can set `var['rate']` via a trigger from `$my_address`; any other trigger with `trigger.output[[asset=base]] > 100000` exchanges bytes for asset using `round($bytes_amount * var['rate'])`.
2. Victim broadcasts a payment unit to the AA address expecting `var['rate']` = R (the currently known/stable rate).
3. Before the victim's unit stabilizes, the admin observes it on the network and broadcasts a `trigger.data.exchange_rate` unit setting `var['rate']` to a near-zero value, engineering its DAG placement (parent/level selection) so it stabilizes with an earlier `level` in the ordering used by `main_chain.js`'s `ORDER BY units.level, units.unit, address` for the same MCI.
4. When triggers execute in `handleAATriggers`'s deterministic order, the admin's rate-change trigger runs first, and the victim's exchange trigger then computes `$asset_amount = round($bytes_amount * var['rate'])` using the manipulated near-zero rate, paying the victim almost nothing for their bytes.

### Citations

**File:** main_chain.js (L1691-1706)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```

**File:** aa_composer.js (L59-88)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
```

**File:** aa_composer.js (L1865-1886)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
			var messages = template.messages;
			if (!messages)
				return bounce('no messages');
			// this will also filter out the special message that performs the state changes
			messages = messages.filter(function (message) { return (isNonemptyObject(message) && 'payload' in message && (message.app !== 'payment' || isNonemptyObject(message.payload) && Array.isArray(message.payload.outputs))); });
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
			messages.forEach(function (message) {
				var payload = message.payload;
				if (message.app === 'asset' && isNonemptyArray(payload.denominations) && payload.denominations.every(d => isNonemptyObject(d) && ValidationUtils.isPositiveInteger(d.denomination)))
					payload.denominations.sort(sortDenominations);
				if ((message.app === 'asset' || message.app === 'asset_attestors') && isNonemptyArray(payload.attestors) && payload.attestors.every(ValidationUtils.isValidAddress))
					payload.attestors.sort();
			});
			sendUnit(messages);
		});
```

**File:** test/samples/sell_asset_for_bytes.oscript (L19-37)
```text
			{ // update exchange rate
				if: "{trigger.data.exchange_rate AND trigger.address == $my_address}",
				messages: [{
					app: 'state',
					state: "{ var['rate'] = trigger.data.exchange_rate; response['message'] = 'set exchange rate to '||var['rate']||' tokens/byte'; }"  // asset-units/byte
				}]
			},
			{ // exchange
				if: "{trigger.output[[asset=base]] > 100000}",
				init: "{ $bytes_amount = trigger.output[[asset=base]]; $asset_amount = round($bytes_amount * var['rate']); response['message'] = 'exchanged '||$bytes_amount||' bytes for '||$asset_amount||' asset.'; }",
				messages: [{
					app: 'payment',
					payload: {
						asset: "n9y3VomFeWFeZZ2PcSEcmyBb/bI7kzZduBJigNetnkY=",
						outputs: [
							{address: "{trigger.address}", amount: "{ $asset_amount }"}
						]
					}
				}]
```
