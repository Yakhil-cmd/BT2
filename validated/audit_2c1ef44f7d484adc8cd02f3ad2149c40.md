Based on the report's bug class — a downstream distribution/consumption path being skipped due to a condition based on an unrelated resource, permanently stranding funds — the closest reachable analog in `ocore` is in the AA-trigger detection query in `main_chain.js`.

### Title
AA triggers are never created for private-asset payments, permanently freezing AA-held private-asset funds - (File: main_chain.js)

### Summary
`main_chain.js`'s `handleAATriggers()` builds the list of AA triggers to fire for a stabilized MC index by selecting outputs sent to AA addresses, but it filters the outputs with `(outputs.asset IS NULL OR is_private=0)` [1](#0-0) . Just like `Voter.distribute()` only invokes `Gauge.deliverBribes()` when an unrelated threshold on the base-token reward holds — leaving bribe rewards stuck whenever that condition is false — here the only mechanism that can ever cause an AA to act on and move its received funds (the `aa_triggers` row that leads to `handleTrigger()`/`sendUnit()`) is gated on `is_private=0`. Any private-asset output sent to an AA address is silently excluded from ever producing a trigger.

### Finding Description
An AA's balance can only be spent through `sendUnit()`/`completePaymentPayload()`, which is reachable exclusively via `handleTrigger()`, itself only invoked for rows inserted into `aa_triggers` by `handleAATriggers()` [2](#0-1) . The SQL that populates `aa_triggers` explicitly excludes private-asset outputs (`is_private=0`), so a private-asset payment sent to an AA address never creates a trigger row and the AA never processes it. Consistent with this, `storage.insertAADefinitions()` also excludes private outputs when computing an AA's spendable balance (`AND (is_private=0 OR is_private IS NULL)`) [3](#0-2) , and `aa_composer.js` explicitly refuses to let an AA *send* a private asset ("it'll fail validation anyway due to lack of spend_proofs") [4](#0-3) .

The net effect: any private-payment counterparty who sends a private-asset payment to an AA address creates an output that the AA can never see, never account for, and never move — it is permanently unreachable by any code path in the protocol, exactly analogous to the Bribe rewards being stranded because the only call site that could release them (`deliverBribes()`) is gated behind an unrelated condition.

### Impact Explanation
Funds sent as a private asset to any AA address become permanently frozen: they are not included in `aa_balances`, they never trigger AA logic, and the AA has no other mechanism to acknowledge or forward them. This matches the "AA fund loss or freezing" impact category — coins are irrecoverably locked at the AA's address with no path to redemption, mirroring the "rewards can be locked" characterization of the original finding.

### Likelihood Explanation
This is trivially reachable by any unprivileged private-payment counterparty: composing and sending a private-asset payment (e.g., a private divisible/indivisible asset transfer) with an output addressed to any known AA address is a normal user-level operation requiring no special privileges, hub cooperation, or protocol exploitation. There's no user-facing warning that stops a wallet from constructing such a payment.

### Recommendation
Either (a) reject/validate private-asset payments whose output address is a known AA address at composition/validation time (mirroring the existing check that already forbids AAs from *sending* private assets), so users cannot accidentally lock funds this way, or (b) extend the trigger-detection and AA balance-accounting queries to also account for private-asset outputs sent to AA addresses so such funds are not silently dropped, and clearly document/refund the case where an AA cannot process a private payment it received.

### Proof of Concept
1. Deploy any AA (e.g., a trivial autonomous agent responding to `base` triggers) — note its address `AA_ADDR`.
2. From a wallet, compose a private-asset payment (any asset with `is_private=true`) with an output sending funds to `AA_ADDR`.
3. Broadcast and let the unit stabilize.
4. Observe that `handleAATriggers()`'s query in `main_chain.js` never selects this output (due to `is_private=0` filter) [5](#0-4) , so no row is inserted into `aa_triggers`, and `aa_balances` for `AA_ADDR` is never credited for this output [3](#0-2) .
5. The private-asset output at `AA_ADDR` remains unspent forever — the AA has no way to trigger on it or move it out, verifying permanent fund freezing.

### Citations

**File:** main_chain.js (L1691-1723)
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
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
	}
```

**File:** storage.js (L960-960)
```javascript
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
```

**File:** aa_composer.js (L1329-1330)
```javascript
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```
