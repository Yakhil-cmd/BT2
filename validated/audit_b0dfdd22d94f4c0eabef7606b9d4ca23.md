### Title
Autonomous Agent payments to attacker-controlled addresses auto-trigger malicious secondary AAs, whose bounce forces reversion of the trusted AA's entire response - ([File: aa_composer.js])

### Summary
The reported bug class is "governance can be tricked into performing external calls to a malicious contract" — a trusted/privileged component (`Incentivizer`/`ReserveSwapper`) makes an external call to an address whose code is attacker-controlled (a fake ERC20), and that external call can produce unexpected side effects on the trusted contract's execution flow. In `ocore`, Autonomous Agents (AAs) play the role of "smart contracts", and any payment sent from one AA to another address automatically and unconditionally triggers that recipient's oscript code if the recipient turns out to be an AA — this is the ocore analog of a Solidity "external call". Because the recipient address of an AA's payment is frequently derived from untrusted input (`trigger.address`, `trigger.data`, or state vars fed by earlier users), an attacker can deploy their own malicious AA at an address that a legitimate/trusted "governance-like" AA will pay, causing that malicious AA's arbitrary logic to run as a "secondary trigger". If the attacker's AA deliberately bounces, the entire chain — including all state changes and payments already computed by the trusted AA — is reverted, exactly mirroring the concern in the original report about reducing “attack surface” for external calls made on privileged code paths.

### Finding Description
Every unit sent by an AA is scanned for output addresses; if any of them is itself a registered AA address, `handleSecondaryTriggers` automatically invokes `handleTrigger` on that address, feeding it the just-sent payment as a trigger: [1](#0-0) 

This is architecturally identical to a Solidity contract making an external call to a recipient contract with attacker-controlled code (the `rescue`/`swap` external-call pattern in the referenced report), except here the "external call" is unconditional and automatic — ocore itself invokes the recipient's arbitrary oscript whenever a payment output matches a known AA address, without any opt-in or allow-listing by the sending AA.

If that secondary (malicious) AA's code decides to bounce (e.g., by calling `bounce(...)` in its own oscript, which is standard, always-available AA behavior), the failure propagates back up the call chain: [2](#0-1) 

For a primary trigger, a bounce from any secondary AA forces `revert(...)` of the *entire* chain, undoing all state variable and balance updates made by the trusted/"governance" AA in that same trigger processing, even though the trusted AA's own logic was semantically legitimate. The trusted AA's payment output address is very often attacker-influencable: many AA templates route funds to `trigger.address` (the immediate caller of the trigger, who can be any address, including one the attacker just defined as a malicious AA) or to addresses read from user-controlled `trigger.data`/state variables, as seen throughout the codebase's own sample AAs (e.g. `test/samples/fundraising_proxy.oscript`, `test/samples/create_an_asset.oscript`, and multiple test-suite AAs sending to `{trigger.address}`/`{trigger.initial_address}`).

The bounce logic itself confirms secondary triggers behave differently and permanently fail the parent flow on error: [3](#0-2) 

### Impact Explanation
An attacker can deploy a malicious AA and interact with any legitimate "governance"/protocol AA (e.g., a DAO, DEX, lending, or fundraising AA) whose payout logic sends funds to an address supplied or influenced by the caller (a very common oscript pattern, matching the original audit's concern about "external calls to a malicious contract" originated from a privileged component). By forcing the malicious secondary AA to bounce, the attacker can:
- Force reversion of the parent AA's state updates and payment outputs for that trigger, wasting the bounce fees paid by the (possibly innocent) triggering unit and denying the intended recipients their expected payout for that specific interaction (fund freezing/denial of service for that flow).
- Repeatedly grief a protocol AA that automatically forwards funds to attacker-chosen or attacker-influenced addresses, similar in spirit to the original report's concern that governance-controlled contracts should not blindly trust code reachable via external calls.

This does not directly enable double-spend or asset inflation, but it does allow an unprivileged attacker to disrupt the deterministic success of a trusted AA's execution and cause fund-flow/state inconsistency for specific triggers — a Medium-severity impact consistent with the source report's rating (funds were not stolen there either, but the "reduce attack surface for external calls from privileged code" recommendation directly applies).

### Likelihood Explanation
Likelihood is high for any AA design that pays to `trigger.address`/`trigger.initial_address` or to any address taken from trigger data/state vars without verifying it is not (or restricting it from being) a maliciously-deployed AA — a pattern present in the codebase's own official sample scripts (`fundraising_proxy.oscript`, `create_an_asset.oscript`, and the test-suite "chain of AAs" pattern). Defining an AA at an attacker-chosen address is permissionless and requires no special access, so any attacker can pre-compute/deploy an AA and get a "trusted" protocol AA to unknowingly pay it, triggering the malicious logic.

### Recommendation
- Document and strongly recommend that AA authors avoid sending payments to untrusted/attacker-influenced addresses when those payments are expected to always succeed as part of multi-step protocol logic, or explicitly design bounce-tolerant flows (isolate side effects that must not be reverted by a downstream secondary AA failure).
- Consider providing AA template/tooling guidance (analogous to the "acceptable ERC20 properties" guide referenced in the original report) that flags patterns like sending protocol funds to `trigger.address`/user-supplied addresses without isolating that transfer from other critical state changes in the same trigger.
- Evaluate whether secondary-trigger bounces should be scoped to not force reversion of the entire primary chain's already-validated state updates that are unrelated to the bounced secondary AA, reducing the blast radius of an intentionally-hostile downstream AA.

### Proof of Concept
1. Attacker deploys a malicious AA `M` whose only logic is `bounce("griefing")` unconditionally when triggered.
2. Attacker sends a triggering unit with `trigger.address = M` (i.e., `M`'s address is the caller/from-address) to a legitimate "governance-style" protocol AA `G`, whose messages include a payment step that forwards residual/refund funds back to `{trigger.address}` (a very common oscript idiom, as seen in `test/aa_composer.test.js` "chain of AAs" test and `fundraising_proxy.oscript`).
3. `G` executes its normal logic, computing state updates and a payment output to `M`.
4. `handleSecondaryTriggers` (`aa_composer.js:1702`) detects that the output address `M` is a registered AA and automatically invokes `handleTrigger` on `M` as a secondary trigger.
5. `M` immediately bounces.
6. Per `aa_composer.js:1742-1755`, this causes `revert(...)` of `G`'s entire response for that trigger unit — all of `G`'s intended state changes and payments for that unit are undone, even though `G`'s own logic was valid and unrelated to `M`'s malicious behavior.

Note: I was not able to fully inspect the standalone `revert()` function body within the available index (only `addResponse`/`finish`/`bounce` bodies were retrievable); a Devin session with full repository access would be needed to confirm the exact state-rollback mechanics of `revert()` beyond what is shown in the `handleSecondaryTriggers` call site.

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

**File:** aa_composer.js (L1702-1741)
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
```

**File:** aa_composer.js (L1742-1755)
```javascript
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
```
