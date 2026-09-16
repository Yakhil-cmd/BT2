## Title
Unhandled `throw Error()` in witnessing/headers-commission input validation crashes the node on a specific attacker-craftable payment input - (File: `validation.js`)

### Summary
`CVE-2024-21050` describes a DML-triggered hang/crash in MySQL Server caused by insufficient input handling that leads to an availability failure. The structurally closest reachable analog in ocore is a payment-input DML-style validation path in `validatePaymentInputsAndOutputs()` that turns a normal validation failure into an uncaught JS exception, which the process-level `uncaughtException` handler in `network.js` deliberately re-throws to crash the node (`throw err; // crash the process to avoid ending up in an inconsistent state`).

### Finding Description
When validating a payment message with a `headers_commission` or `witnessing` type input, `validatePaymentInputsAndOutputs()` in `validation.js` calls `calcFunc` (either `mc_outputs.calcEarnings` or `paid_witnessing.calcWitnessEarnings`) with callbacks: [1](#0-0) 

The `ifError` callback does **not** propagate the error through the normal validation `cb(err)` channel (which would produce a graceful `ifUnitError`/`ifTransientError` response to the peer); instead it does `throw Error(err)`. This throw occurs inside an asynchronous DB-query callback (`conn.query(..., function(count_rows){ ... callbacks.ifError(...) })` in `paid_witnessing.calcWitnessEarnings`), meaning it cannot be caught by any surrounding `try/catch` in the validation call stack — it becomes an uncaught exception at the event-loop level. [2](#0-1) 

The `ifError` branch fires when `count_rows[0].count !== constants.COUNT_MC_BALLS_FOR_PAID_WITNESSING+2`, i.e., when the number of currently-stable main-chain units following `to_main_chain_index` does not match the expected fixed window. The unit-level checks in `validation.js` only bound `to_main_chain_index` by `paid_witnessing.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci)` — they do not re-verify, at the moment of `calcFunc` execution, that the exact count of stable units still matches, and this window can legitimately be affected by ongoing MC stabilization/timing (the pool of "spendable" MCIs is calculated relative to `last_ball_mci` from the trigger unit’s validation state, while the live table of stable units can change between when the bound is computed and when the count check runs). Because the whole condition is reachable purely from unit fields under attacker control (`from_main_chain_index`, `to_main_chain_index`, input `type`, `address`), an ordinary, unprivileged unit author can post a payment input designed to land in this edge and hit `throw Error(...)`.

Any process-wide `uncaughtException` triggers the network layer's forced crash: [3](#0-2) 

### Impact Explanation
An uncaught exception thrown from inside asynchronous unit-validation code crashes the whole hub/full node process (the codebase explicitly re-throws in the `uncaughtException` handler to force a crash rather than risk running with an inconsistent state). Since unit validation of an untrusted, newly received/posted unit is exactly the code path that reaches this `throw`, a single malicious/malformed but structurally valid unit can repeatedly crash any full node or hub that processes it, denying service to legitimate users trying to get their units confirmed — this matches the "hang or frequently repeatable crash (complete DOS)" characterization of CVE-2024-21050, mapped onto ocore's node-disagreement/availability guarantees ("a network unable to confirm new units" if propagated widely).

### Likelihood Explanation
Reaching this specific `throw` requires the attacker to construct a `headers_commission`/`witnessing` input whose `from_main_chain_index`/`to_main_chain_index` pass the earlier bound checks in `validation.js` (`to_main_chain_index <= max_mci`) yet still cause the live stable-unit count check in `paid_witnessing.calcWitnessEarnings` to fail. This is plausible around chain-stabilization boundaries/timing edges but I could not fully confirm, without deeper access to `getMaxSpendableMciForLastBallMci`'s exact guarantees and the live-state semantics of `is_on_main_chain`/`is_stable`, whether this mismatch can be deterministically and repeatably engineered by an attacker versus only occurring under rare race conditions. This uncertainty lowers confidence from "certain" to "likely, pending confirmation."

### Recommendation
- Change `ifError` in `validatePaymentInputsAndOutputs()` (validation.js, lines ~2590-2592) to call `cb(err)` (or a proper `ifUnitError`/transient error) instead of `throw Error(err)`, so malformed/edge-case inputs are rejected gracefully rather than crashing the process.
- Audit other validation-time `throw Error(...)` calls inside async DB-callback closures in `validation.js` (e.g., near lines 2440-2460, 2591) for the same unhandled-throw-from-async-callback pattern, since any of them reachable from attacker-supplied unit data represents an equivalent DoS.
- Add regression tests that specifically construct witnessing/headers_commission inputs at the stabilization boundary to ensure the "not enough stable MC units" path is exercised without crashing the process.

### Proof of Concept
Not independently confirmed. The concrete PoC would be a unit whose sole author posts a payment message with an input `{type: "witnessing", from_main_chain_index: X, to_main_chain_index: Y}` (or `headers_commission`) where `Y <= paid_witnessing.getMaxSpendableMciForLastBallMci(last_ball_mci)` but where, at the moment `calcWitnessEarnings` executes its `is_on_main_chain=1 AND is_stable=1` count query, the number of stable units in the range `[Y, Y+COUNT_MC_BALLS_FOR_PAID_WITNESSING+1]` is not exactly `COUNT_MC_BALLS_FOR_PAID_WITNESSING+2`. I was not able to fully verify, with the available context, an exact deterministic set of field values that reliably produces this mismatch on a synced node — this would require running the code or examining `getMaxSpendableMciForLastBallMci`/`readNextSpendableMcIndex` and live DB state more closely than the indexed context allows. I recommend starting a Devin session with full repository and runtime access to construct and verify a concrete failing unit.

### Citations

**File:** validation.js (L2588-2599)
```javascript
						var calcFunc = (type === "headers_commission") ? mc_outputs.calcEarnings : paid_witnessing.calcWitnessEarnings;
						calcFunc(conn, type, input.from_main_chain_index, input.to_main_chain_index, address, {
							ifError: function(err){
								throw Error(err);
							},
							ifOk: function(commission){
								if (commission === 0)
									return cb("zero "+type+" commission");
								total_input += commission;
								checkInputDoubleSpend(cb);
							}
						});
```

**File:** paid_witnessing.js (L15-25)
```javascript
function calcWitnessEarnings(conn, type, from_main_chain_index, to_main_chain_index, address, callbacks){
	conn.query(
		"SELECT COUNT(1) AS count FROM units WHERE is_on_main_chain=1 AND is_stable=1 AND main_chain_index>=? AND main_chain_index<=?", 
		[to_main_chain_index, to_main_chain_index+constants.COUNT_MC_BALLS_FOR_PAID_WITNESSING+1], 
		function(count_rows){
			if (count_rows[0].count !== constants.COUNT_MC_BALLS_FOR_PAID_WITNESSING+2)
				return callbacks.ifError("not enough stable MC units after to_main_chain_index");
			mc_outputs.calcEarnings(conn, type, from_main_chain_index, to_main_chain_index, address, callbacks);
		}
	);
}
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
