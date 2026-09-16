### Title
Funds forwarded to a downstream AA via a secondary trigger are never returned when that AA bounces, permanently locking them - (File: `aa_composer.js`)

### Summary
The Malda/Across bug locks bridged funds because the bridge's `depositV3Now` refund path returns failed transfers to the `Rebalancer` contract, which has no logic to forward or reclaim them. `ocore`'s Autonomous Agent (AA) engine has a structurally identical dead-end: when one AA forwards a payment to another AA as a *secondary trigger* (an AA-to-AA call chain within a single unit's cascading responses), and the receiving AA's formula execution bounces, the built-in automatic bounce-refund mechanism is explicitly skipped for secondary triggers. The forwarded asset is already committed to the receiving AA's balance in a final, on-DAG payment and there is no protocol-level path to move it back to the original sender or trigger address unless the receiving AA's own oscript happens to contain bespoke recovery logic for that exact failure state.

### Finding Description
When a primary AA response contains a `payment` message addressed to another AA, and that AA is invoked as a secondary trigger, `handleTrigger` is called with `bSecondary=true` [1](#0-0) . If the secondary AA's formula evaluation fails, `bounce()` is invoked to unwind that response, but the function explicitly disables the auto-refund logic for secondary triggers:

```
if (bBouncing)
    return finish(null);
bBouncing = true;
if (bSecondary)
    return finish(null);
``` [2](#0-1) 

For a *primary* trigger, `bounce()` builds `payment` messages that send the received funds back to `trigger.address` provided enough bounce fees were supplied [3](#0-2) . For a *secondary* trigger this entire refund path is bypassed (`return finish(null)`), meaning no bounce-response unit is generated and no attempt is made to return the payment that had already been sent to the bounced AA in the earlier (already-committed) response unit.

Crucially, the payment to the downstream AA is not conditional on that AA's success: it is part of the upstream AA's own response unit, which is validated and saved to the DAG (`validateAndSaveUnit`) before the downstream AA is even evaluated [4](#0-3) . Only afterward is `handleSecondaryTriggers` invoked to process the downstream AA. If that downstream evaluation bounces, the coins are irreversibly part of the downstream AA's balance (a final ledger state), while the bounce path guarantees no refund message is produced. This is directly analogous to Across's `depositV3Now` sending funds with the `Rebalancer` as `depositor`: the recipient of a failed operation has no protocol-enforced path back to the sender, and any recovery is entirely dependent on whether that specific contract (or in this case, the downstream AA's oscript author) happened to anticipate and code a rescue/forward mechanism for that exact scenario.

### Impact Explanation
Any multi-AA composition pattern where an unprivileged AA-trigger sender causes AA A to forward assets to AA B as a secondary trigger (a common and documented pattern - "calling a remote function", proxy/aggregator AAs, cross-AA payment forwarding) can result in permanent, protocol-level fund loss if B's execution bounces on that forwarded payment for any reason the AA author of B did not foresee (unexpected trigger data shape, unanticipated state combination, insufficient bounce fees on B's own downstream calls, a formula error, etc.). Because bounce-refund is unconditionally disabled for secondary triggers, there is no fallback: the sent asset is stuck at B's address, inaccessible to A, to the original human user, or to any generic recovery mechanism - matching the "funds intended for [inter-agent] transfer become locked" impact class of the referenced report.

### Likelihood Explanation
This is reachable by any unprivileged AA-trigger sender: simply sending a trigger to a composing AA A that forwards value to a helper/destination AA B is a normal, encouraged usage pattern (seen in the "fundraising proxy" and "remote function call" samples in the test suite) [5](#0-4) [6](#0-5) . Triggering B to bounce on the exact forwarded payload is within the trigger sender's control in many designs (e.g., supplying trigger data or timing that causes B's `if`/`init` clauses to fail), making exploitation straightforward whenever A's downstream target B is not defensively coded to always succeed or explicitly return unhandled payments.

### Recommendation
Consider extending the bounce mechanism so that a bounced secondary trigger automatically returns the payment it received to the AA (or original `trigger.initial_address`) that sent it, mirroring the primary-trigger auto-refund behavior in `bounce()`, instead of unconditionally discarding the response with `finish(null)` when `bSecondary` is true. At minimum, document this design limitation prominently so AA authors are required to implement fallback/rescue logic for every payment case they might receive, and consider providing a standard "generic default handler that returns unrecognized payments" pattern/helper as part of the AA framework.

### Proof of Concept
1. Deploy AA `A` whose response to a user trigger includes a `payment` message forwarding received bytes to AA `B` (secondary trigger), following the pattern used in `test/aa_composer.test.js:1066-1094` ("calling a remote function").
2. Craft AA `B` (or reuse an existing AA) such that, for the specific trigger data/state combination produced by `A`'s forwarded message, `B`'s `init`/`bounce_fees` logic bounces (e.g., insert a `bounce(...)` condition that the attacker can trigger via `trigger.data` passed through `A`).
3. Post a unit to `A` that causes it to forward funds to `B` under conditions that make `B` bounce.
4. Observe that `A`'s response unit (containing the payment to `B`) is committed to the DAG as final, but `B`'s bounce, per `aa_composer.js:926-927`, produces no refund response - the funds remain at `B`'s address with no path back to `A` or the original user.

### Citations

**File:** aa_composer.js (L399-423)
```javascript
// the result is onDone(objResponseUnit, bBounced)
function handleTrigger(conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone) {
	var trigger_opts;
	if (arguments.length === 1) {
		trigger_opts = conn;
		conn = trigger_opts.conn;
		batch = trigger_opts.batch;
		trigger = trigger_opts.trigger;
		params = trigger_opts.params;
		stateVars = trigger_opts.stateVars;
		arrDefinition = trigger_opts.arrDefinition;
		address = trigger_opts.address;
		mci = trigger_opts.mci;
		objMcUnit = trigger_opts.objMcUnit;
		bSecondary = trigger_opts.bSecondary;
		arrResponses = trigger_opts.arrResponses;
		onDone = trigger_opts.onDone;
		// extra options:
		// trigger_opts.bAir
		// trigger_opts.assocBalances
		if (!!trigger_opts.bAir !== !!trigger_opts.assocBalances)
			throw Error("assocBalances and bAir do not match");
	}
	else
		trigger_opts = { conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone };
```

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

**File:** aa_composer.js (L1403-1419)
```javascript
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
									if (arrOutputAddresses.length === 0)
										return finish(objUnit);
									fixStateVars();
									addResponse(objUnit, function () {
										updateStorageSize(function (err) {
											if (err)
												return revert(err);
											handleSecondaryTriggers(objUnit, arrOutputAddresses);
```

**File:** test/samples/fundraising_proxy.oscript (L44-86)
```text
			{ // contribute
				if: `{trigger.output[[asset=base]] >= 1e5 AND $asset}`,
				init: `{
					if (var[$destination_aa]['finished'])
						bounce('game over');
					$amount = trigger.output[[asset=base]] - 2000; // to account for fees we need to respond now and to refund bytes or pay shares later
					$total_raised = var['total_raised'] + $amount;
					$missing_amount = ceil((balance[$destination_aa][base] + $total_raised)*0.51) - var[$destination_aa]['team_' || $team || '_amount'];
					$bDone = ($total_raised > $missing_amount);
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [{address: "{trigger.address}", amount: "{$amount}"}]
						}
					},
					{
						if: `{$bDone}`,
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [{address: "{$destination_aa}", amount: "{$total_raised}"}]
						}
					},
					{
						if: `{$bDone}`,
						app: 'data',
						payload: {
							team: "{$team}"
						}
					},
					{
						app: 'state',
						state: `{
							if ($bDone)
								var[$asset || '_status'] = 'raised';
							else
								var['total_raised'] = $total_raised;
						}`
					}
				]
```

**File:** test/aa_composer.test.js (L1066-1094)
```javascript
test.cb.serial('calling a remote function', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var remote_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		getters: `{
			$f = ($x) => {
				{
					sq: $x^2,
					this: this_address,
					bal: balance[base]
				}
			};
		}`,
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
					]
				}
			}
		]
	}];
```
