I now have enough evidence to confirm the analog. In ocore, an "unprivileged" AA definer (analogous to the "bull") can deploy a secondary AA that always bounces, causing any primary AA that pays it (analogous to the "bear" trying to `settleContract()`) to have its **entire response reverted**, indefinitely blocking settlement.

### Title
Malicious secondary AA can force `revert()` of a primary AA's settlement response, permanently blocking counterparty settlement - (File: aa_composer.js)

### Summary
Any address can define an Autonomous Agent (AA) whose only behavior is to always `bounce()`. If a legitimate escrow/settlement AA (e.g. an options/futures/bet contract, analogous to `settleContract()` in the reported bug) pays out to a counterparty-controlled AA address as part of its normal settlement logic, that payment becomes a "secondary trigger." If the secondary AA always bounces, `handleSecondaryTriggers()` treats this as a fatal error and calls `revert()`, which rolls back **the entire primary AA response**, including all of its state changes, not just the outgoing payment.

### Finding Description
When a primary AA's response unit contains outputs to another AA address, `handleTrigger()` recursively invokes that AA as a "secondary trigger" via `handleSecondaryTriggers()`: [1](#0-0) 

If the secondary AA's execution bounces, the callback receives a `bounce_message` and propagates it as an error: [2](#0-1) 

The `async.eachSeries` completion handler then calls `revert()` on the **primary** (non-secondary) AA, explicitly because "one of secondary AAs bounced": [3](#0-2) 

`revert()` rolls back all AA balance/state changes to the savepoint taken before the primary trigger was processed, discards all previously computed responses in the chain, and finally calls `bounce()` on the primary trigger itself: [4](#0-3) 

Because a secondary AA's own bounce is unconditional and controlled entirely by its author's oscript (e.g. a getter/`init` formula that always calls `bounce(...)`), an attacker who controls the payout address specified by the trigger sender (or hard-coded in the settlement AA's logic as "pay the counterparty") can make that address a malicious AA that always bounces. Every time the victim tries to trigger settlement, the settlement AA's payment to the attacker's AA fails, which forces `revert()` on the whole primary trigger, undoing the victim's attempted settlement and returning only the bounced trigger amount (minus bounce fees) to the victim — the underlying escrowed funds/state managed by the primary AA remain frozen, untouched, and inaccessible, exactly like the `settleContract()` DoS in the reported bug where a malicious `to` address blocks `safeTransferFrom`.

This mirrors the reported vulnerability class: a single unprivileged party (the payment recipient) can, through code they control at an address the protocol will pay, unconditionally block completion of a settlement/finalization step that the victim needs to execute, causing permanent loss of access to escrowed funds or inability to exercise contractual rights.

### Impact Explanation
Any AA-based escrow, options, futures, prediction-market, or payment-channel contract (see samples such as `option_contract.oscript`, `futures_contract.oscript`, `payment_channels.oscript`) that pays out to a counterparty address as part of settling/closing logic is vulnerable if that counterparty address can be an AA under the counterparty's control. The counterparty can deploy a "self-destructing" bounce-only AA as its payout address, then refuse to ever accept the payout, indefinitely reverting and thus freezing settlement for the other, honest party. This is a fund-freezing/denial-of-settlement issue (High), analogous to the `bull can prevent settleContract()` finding, since it lets one party unilaterally and repeatedly veto a state transition that should be executable unilaterally by the counterparty. [5](#0-4) 

### Likelihood Explanation
Likelihood is High for any AA whose payout address is attacker-influenced (e.g., a counterparty in a bilateral contract, or any protocol where a party's own address is used as the payment destination in a secondary-trigger chain). Creating a bounce-only AA is trivial and cheap (`init: "{ bounce(\"always\"); }"`), and the attacker only needs to ensure they receive/settle via their AA address rather than a plain wallet address.

### Recommendation
Consider decoupling the atomicity of the primary AA's own state changes from the success/failure of any downstream secondary AA trigger. For example: (1) do not `revert()` the entire primary response when a secondary AA bounces — instead let the primary AA's payment/state changes stand, and treat the secondary AA's failure only as informational (the secondary receives/keeps or bounces its own funds independently); or (2) provide a documented pattern/best practice (and possibly a protocol-level "pull-payment" idiom) so contract authors avoid unconditionally reverting on counterparty-controlled payees, similar to how `bounce_fees` already protect the *primary* trigger sender from unrecoverable loss but currently provide no protection against a malicious *secondary* recipient's induced revert of the whole chain.

### Proof of Concept
1. Deploy `attacker_aa`:
```
['autonomous agent', {
  init: "{ bounce('always bounce'); }",
  messages: [{ app: 'state', state: "{}" }]
}]
```
2. Deploy `settlement_aa` whose settlement branch pays `trigger.data.counterparty_aa` (or a stored address controlled by the counterparty) the escrowed amount as part of its response messages, mirroring the pattern in `test/aa_composer.test.js`'s "chain of AAs" test where a primary AA pays a secondary AA address: [6](#0-5) 
3. Victim triggers `settlement_aa` to settle/exercise their side of the contract; `settlement_aa`'s response includes a payment output to `attacker_aa`.
4. `handleSecondaryTriggers()` invokes `attacker_aa`, which bounces unconditionally.
5. `revert({message: "one of secondary AAs bounced with error: ..."})` is called on `settlement_aa`'s primary trigger, rolling back all state changes and only bouncing the trigger amount back to the victim — the settlement never completes, and the victim can retry indefinitely with the same result. [3](#0-2)

### Citations

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

**File:** aa_composer.js (L1743-1750)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
```

**File:** aa_composer.js (L1759-1783)
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
```

**File:** test/samples/option_contract.oscript (L74-85)
```text
			{ // pay bytes in exchange for the winning asset
				if: "{trigger.output[[asset!=base]] > 1000 AND var['winner'] AND trigger.output[[asset!=base]].asset == var[var['winner'] || '_asset']}",
				messages: [{
					app: 'payment',
					payload: {
						asset: "base",
						outputs: [
							{address: "{trigger.address}", amount: "{ trigger.output[[asset!=base]] }"}
						]
					}
				}]
			},
```

**File:** test/aa_composer.test.js (L190-212)
```javascript
	var primary_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: secondary_address, amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
			{
				app: 'state',
				state: `{
					var['who'] = trigger.address || timestamp;
					var['initial'] = trigger.initial_address || timestamp;
					var['large_num'] = 1e15;
					var['long_num'] = 0.000678901234567;
				}`
			}
		]
	}];
```
