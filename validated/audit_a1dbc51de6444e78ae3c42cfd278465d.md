This confirms the mechanism: `revert()` at `aa_composer.js:1759-1783` rolls back to `SAVEPOINT initial_balances`, clears all `stateVars` and `arrResponses`, and then calls `bounce()` on the *entire primary trigger chain* whenever a secondary (descendant) AA in the chain bounces. Combined with the fact that secondary triggers are explicitly exempted from needing to cover bounce fees (`aa_composer.js:1850-1854`, "being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced"), this creates a free "peek-then-reject" primitive analogous to BetHash's `dicereceipt()` callback abuse.

### Title
Free outcome-peeking and unconditional reversal via secondary-AA bounce enables guaranteed-win exploitation of probabilistic/casino-style AAs - (File: aa_composer.js)

### Summary
Any user can deploy their own Autonomous Agent (AA) to serve as the "player" address in a probabilistic payout AA (e.g. a dice/lottery AA that pays a variable amount depending on some outcome). Because a payment from the primary AA to another AA address automatically triggers that AA as a secondary trigger, the attacker's AA gets to inspect the real outcome (the amount/asset it received, any accompanying data) *before* deciding whether to keep it. If the outcome is unfavorable, the attacker's AA can deliberately bounce, and this bounce is exempt from covering bounce fees and cascades into a full `revert()` of the whole trigger chain, undoing all balance and state changes for every AA involved, including the "casino" AA. The attacker only loses the header/payload commission of the posted unit, and can then repost the exact same bet to try again — a bug-class directly analogous to the BetHash incident, where the attacker used inline notification hijacking to conditionally reject bets after seeing the outcome, retrying essentially for free.

### Finding Description
When a primary trigger causes an AA to send a payment to another AA address, `handleSecondaryTriggers()` builds a `child_trigger` from the produced payment/state and re-enters `handleTrigger()` for that AA (`aa_composer.js:1702-1741`). The secondary AA's `oscript` logic runs with full knowledge of the trigger data at hand — e.g., the amount actually received (win/lose result of a casino/lottery-style primary AA).

If the secondary AA chooses to bounce (e.g., via an `if` condition that only succeeds when the received amount looks favorable, otherwise producing "no messages" or an explicit throw/`bounce()`), two properties make this free and total:

1. `aa_composer.js:1850-1854` explicitly skips the bounce-fee requirement for secondary triggers: *"being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced."*
2. In `handleSecondaryTriggers()`, when a child call returns a `bounce_message`, and the current AA is itself non-secondary (i.e., is the top-level "casino"), the code calls `revert()` instead of just bouncing the secondary branch (`aa_composer.js:1743-1750`): *"one of secondary AAs bounced with error"*.
3. `revert()` (`aa_composer.js:1759-1783`) rolls back the DB to `SAVEPOINT initial_balances`, clears `stateVars` and `arrResponses` for **all** AAs touched in the entire trigger chain (not just the secondary one), and then calls `bounce()` on the primary trigger.

The net effect: the entire economic outcome of the bet — the casino AA's balance change, the state var updates recording the bet, everything — is undone as if the transaction never took bytes/asset value at all. Only the network-level unit fees (header/payload commission) are actually spent, and if the attacker keeps those minimal (a stripped-down oscript with a tiny bet), they can repeatedly "peek and reject" until a favorable outcome is produced, at near-zero net cost — turning any probabilistic AA-based game into a guaranteed win for an attacker willing to run their own AA as the player address.

### Impact Explanation
This breaks the fairness/economic guarantees of any AA that implements a randomized payout (dice, lottery, bet, prize draws, and similar oscript patterns), allowing systematic extraction of funds from such AAs by a single attacker-controlled AA acting as the counterparty, with cost bounded only by unit commission fees rather than by the AA's own designed house edge/bounce fee. Any AA design that pays a secondary-AA-controlled address based on some outcome is vulnerable to unlimited "free rerolls," directly causing fund loss for the AA (and thus honest players/AA owner).

### Likelihood Explanation
Trivially reachable by any unprivileged unit poster: deploying an AA is permissionless, and simply becoming the receiving/secondary address of any probabilistic payout AA (by triggering it as a player) suffices. No special privileges, hub/network position, or race conditions are required — purely oscript logic exploiting the documented free-bounce and full-revert semantics for secondary triggers.

### Recommendation
Reconsider the free-bounce exemption for secondary triggers combined with full-chain revert: either (a) require secondary triggers that bounce to still forfeit the bytes/assets they were about to receive (i.e., don't revert the primary AA's state/balance changes, just fail to deliver to the secondary AA and let those funds stay stuck/returned to primary AA balance), or (b) explicitly document and warn AA authors that sending outcome-dependent payments to another AA address is unsafe because it grants that AA a free reject option, and provide a primitive (e.g., a plain non-AA address requirement, or "no callback" payment mode) for payout recipients in gambling-style AAs so payouts cannot be bounced by the recipient.

### Proof of Concept
1. Deploy "Casino AA" `C` whose `messages` compute a pseudo-random outcome from trigger/unit data and pay a variable amount (e.g., 2x on win, 0 on loss) back to `trigger.address`.
2. Deploy "Player AA" `P` (attacker-controlled) with logic: `if: "{trigger.output[[asset=base]] < 2 * bet_amount}"` triggering a bounce/no-messages response (causing `handleTrigger` to hit `bounce('no messages')` or similar), and otherwise accept and keep the funds.
3. Attacker sends the bet unit with `P` as `trigger.address`, so `C` pays out to `P`.
4. If `C` pays a losing amount, `P`'s secondary trigger bounces at `aa_composer.js:1850-1854` (no bounce fee required) which propagates to `revert()` at `aa_composer.js:1743-1750,1759-1783`, undoing `C`'s balance/state changes entirely.
5. Attacker reposts the same bet; repeat until `C` pays a winning amount, which `P` now keeps. Net attacker cost ≈ sum of unit commissions across failed attempts, not the bet amount itself, guaranteeing eventual profit extraction from `C`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
	}
```

**File:** aa_composer.js (L1702-1757)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
				},
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
	}
```

**File:** aa_composer.js (L1759-1798)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```

**File:** aa_composer.js (L1841-1863)
```javascript
	updateInitialAABalances(function (err) {

		// these errors must be thrown after updating the balances
		if (err)
			return bounce(err);
		if (arrResponses.length >= constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER) // max number of responses per primary trigger, over all branches stemming from the primary trigger
			return bounce("max number of responses per trigger exceeded");
		if ("max_aa_responses" in trigger && arrResponses.length >= trigger.max_aa_responses)
			return bounce(`max_aa_responses ${trigger.max_aa_responses} exceeded`);
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
			// skip this check for dry-run which uses genesis unit as trigger unit
			if (trigger.unit !== constants.GENESIS_UNIT && !trigger_opts.bAir && storage.assocStableUnits[trigger.unit].count_aa_responses && mci >= constants.pemCurvesFixMci)
				return bounce('a second primary trigger from the same unit is not allowed');
		}
```
