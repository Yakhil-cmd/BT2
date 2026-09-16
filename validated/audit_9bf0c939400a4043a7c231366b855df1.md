I have sufficient evidence to establish this analog. The bug class from the report — "funds are credited to a contract address through a path that bypasses the contract's designated 'funds received' handler, so they can never be processed/distributed and are permanently lost" — maps directly onto ocore's AA (Autonomous Agent) trigger mechanism when a private payment is sent to an AA address.### Title
Private-asset payments sent to an AA address are permanently lost — never credited and unspendable - ([File: aa_composer.js], [File: main_chain.js], [File: storage.js])

### Summary
The Sherlock report's root cause is generic: a smart contract's balance is credited through a code path that bypasses the contract's designated "funds received" handler, so the contract never learns about, accounts for, or can distribute those funds. In ocore, the AA (Autonomous Agent) analog of a "receive handler" is the trigger mechanism, which is fed exclusively from `payment` message outputs found in public units. Payments made with a **private asset** (e.g. blackbytes) are explicitly excluded from every step of this pipeline, so bytes/asset value sent to an AA address via a private payment are recorded on-chain as spent-to-that-address, yet are never added to the AA's `aa_balances`, never trigger AA execution, and can never be spent by the AA (or anyone) afterward.

### Finding Description
The AA balance/trigger pipeline filters out private outputs at every stage:

1. When a main-chain index stabilizes, `handleAATriggers()` selects the units that will invoke an AA strictly with `(outputs.asset IS NULL OR is_private=0)` — private outputs are never queued into `aa_triggers`: [1](#0-0) 

2. `getTrigger()` builds `trigger.outputs` from the messages of the (public) unit that was queued as a trigger — a private payment's real amount/asset outputs are not part of the publicly retrievable message content used here, so even if somehow reached, it would not surface as `trigger.outputs`: [2](#0-1) 

3. AA balance bookkeeping (`aa_balances`) is populated/reconciled with an explicit `(is_private=0 OR is_private IS NULL)` condition, both when defining new AAs (backfilling balances) and in the periodic consistency check `checkBalances()`: [3](#0-2) [4](#0-3) 

4. Symmetrically, AAs are themselves forbidden from *sending* private assets ("it'll fail validation anyway due to lack of spend_proofs"): [5](#0-4) 

Together, these confirm that private-asset value is architecturally invisible to the AA subsystem in both directions. Any user (an "unprivileged unit poster") can construct and broadcast a private payment (e.g. of blackbytes, the built-in private divisible asset, or any custom private asset) whose output address is a valid, already-defined AA address. The unit's public portion only carries a `payload_hash` for the private message (the real outputs are exchanged out-of-band between the parties), so:
- The output is recorded in the `outputs` table with `is_private=1` and `address = <AA address>`, `is_spent=0`.
- It never enters `aa_triggers`, never appears in `trigger.outputs`, and never gets added to `aa_balances`.
- No AA code (`bounce`, `state` formula, etc.) ever runs for this payment; there is no way for the AA's own logic to "sweep" or acknowledge it, because AA formulas can only reference `trigger.outputs`/`balance[...]`, which are fed from `aa_balances` and the trigger — neither of which ever see this value.
- The output remains unspent forever with no path to be spent, since only the AA (via `arrConsumedOutputs`/`updateFinalAABalances`) or its owner-key logic can authorize spending from that address, and AAs have no owner keys — they only respond to formula execution driven by triggers.

This is the direct analog of the Solidity bug: value is credited to the target address through a mechanism (private/hidden transfer) that bypasses the only code path (`receive`/AA trigger) capable of accounting for and later distributing it.

### Impact Explanation
Funds (private-asset bytes or tokens) sent to any AA address via a private payment are permanently and irrecoverably lost — locked at an address that has no owner key and whose only spending mechanism (AA trigger/formula execution) can never see or move them. This is a direct, unrecoverable loss of user/protocol funds, matching a Medium/High "AA fund loss/freezing" impact: any DeFi/DEX/wallet AA that a normal user could mistakenly (or a malicious counterparty could deliberately, e.g. to grief an escrow/arbiter AA or hide value out of an accounting system) route a private payment to would have that value stranded forever, and the discrepancy is silently tolerated because `checkBalances()` deliberately excludes private outputs from its consistency check rather than flagging the loss.

### Likelihood Explanation
Likelihood is moderate: it requires the sender to use a private asset (blackbytes or another privacy-enabled asset) and specifically target an AA address, which is unusual but entirely permitted by consensus/validation rules — there is no check in `validatePayment`/`validatePaymentInputsAndOutputs` preventing a private payment's output address from being an AA address, and no wallet-level warning is evident in the reviewed code. Given that AAs are commonly used for bank/exchange-style contracts (e.g. `test/samples/a_bank_without_percent.oscript`) that accept arbitrary assets, and custom private assets can be freely defined and then paid to any address, an attacker or a confused user could realistically trigger this.

### Recommendation
- Reject at validation time any payment whose output address is a known AA address when the asset `is_private` (mirror the existing "trigger address must not be an AA" check for triggers, and add the analogous check inside `validatePaymentInputsAndOutputs`/`validateAATrigger` for private payments), so private funds can never be locked into an AA in the first place.
- Alternatively/additionally, surface a wallet-level warning when a user attempts to send a private-asset payment to an address recognized as an AA (`aa_addresses` table), since silent, permanent fund loss is otherwise indistinguishable from a normal transfer until it's too late.

### Proof of Concept
1. Deploy any AA (e.g. `a_bank_without_percent.oscript`) at address `AA_ADDR`.
2. Issue or hold a private asset (e.g. blackbytes) balance.
3. Construct and broadcast a private payment (`payload_location: 'private'`) whose sole output is `{ address: AA_ADDR, amount: X }` for the private asset, following the same flow as `network.js`'s `handleSavedPrivatePayments` / `wallet.js`'s `handlePrivatePaymentChains`.
4. Observe: the unit stabilizes; `handleAATriggers()` in `main_chain.js` (lines 1695-1706) excludes this output (`is_private=1`) from `aa_triggers`; `aa_balances` for `AA_ADDR` is never updated; `checkBalances()` does not flag any discrepancy because it also filters `is_private=0`.
5. The `X` units of the private asset sent to `AA_ADDR` are now permanently unspendable — no unit can ever reference them as an input under a valid spend condition tied to the AA (AAs have no private/owner keys and only spend via `arrConsumedOutputs` computed from public trigger-driven balances).

Note: I could not fully verify (due to index coverage limits on some files, e.g. the complete `wallet.js`/`private_payment.js` private-chain validation flow) whether there is any wallet-side guard that blocks users from addressing a private payment to an AA before broadcast; if such a guard exists it would reduce likelihood but not the underlying protocol-level lack of enforcement in `validation.js`. I recommend a full-repo Devin session if you want this confirmed against the complete file contents.

### Citations

**File:** main_chain.js (L1695-1706)
```javascript
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

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1963-1979)
```javascript
				var sql_create_temp = "CREATE TEMPORARY TABLE aa_outputs_balances ( \n\
					address CHAR(32) NOT NULL, \n\
					asset CHAR(44) NOT NULL, \n\
					calculated_balance BIGINT NOT NULL, \n\
					PRIMARY KEY (address, asset) \n\
				)" + (conf.storage === 'mysql' ? " ENGINE=MEMORY DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci" : "");
				var sql_fill_temp = "INSERT INTO aa_outputs_balances (address, asset, calculated_balance) \n\
					SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) \n\
					FROM aa_addresses \n\
					CROSS JOIN outputs USING(address) \n\
					CROSS JOIN units ON outputs.unit=units.unit \n\
					LEFT JOIN assets ON outputs.asset=assets.unit \n\
					WHERE is_spent=0 AND sequence='good' AND ( \n\
						is_stable=1 \n\
						OR is_stable=0 AND is_aa_response=1 \n\
					) AND (is_private=0 OR is_private IS NULL) \n\
					GROUP BY address, asset";
```

**File:** storage.js (L954-961)
```javascript
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
```
