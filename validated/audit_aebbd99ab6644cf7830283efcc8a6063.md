### Title
AA fund freezing when bouncing a `spender_attested` asset back to a non-attested trigger address - (File: aa_composer.js)

### Summary
The reported bug class is "push" transfers of tokens to an address that a token-level access-control mechanism refuses to accept, causing funds to become permanently stuck. Ocore's closest analog is the `spender_attested` asset feature, which requires every payment *output* address to be attested by a fixed list of attestors before a transfer can validate [1](#0-0) . When an Autonomous Agent (AA) receives such an asset and later tries to return it to the trigger address (which is exactly what the built-in bounce mechanism does), the return transfer can fail validation if the trigger address is not attested, and the guard against recursive bouncing then causes the AA to swallow the funds with no response unit at all, permanently freezing them in the AA's balance.

### Finding Description
- `spender_attested` assets require every output address of a transfer to be in the attested-address list; otherwise the whole payment message (and thus the whole unit) fails validation with `"some output addresses are not attested"` [1](#0-0) . This is Ocore's structural equivalent of an ERC-20 blacklist: a push to a "denied" address is rejected at the protocol level.
- Any unprivileged user can send a trigger unit to an AA that includes an output of such an asset; the AA's `updateInitialAABalances` immediately credits the AA's balance with the trigger's `outputs`, including the spender_attested asset, regardless of whether the trigger address is attested [2](#0-1) .
- When the AA's own response logic fails (bad formula, insufficient balance, any state-update error, etc.), the framework automatically tries to "push" the received funds back to `trigger.address` via the built-in `bounce()` function, which composes a payment message per asset in `trigger.outputs` addressed to `trigger.address` and calls `sendUnit()` [3](#0-2) .
- `sendUnit()` builds and validates a real unit with `validateAndSaveUnit()` [4](#0-3) , which runs the full protocol validation path, including the `spender_attested` output-address check shown above. If `trigger.address` is not on the attested list for that asset, validation fails and `bounce(err)` is invoked again from inside `sendUnit`'s failure path [4](#0-3) .
- Crucially, `bounce()` guards against infinite recursion with the `bBouncing` flag: on the second entry it simply calls `finish(null)` and gives up, producing no response unit at all [5](#0-4) .
- Because the trigger unit itself (which paid the asset into the AA) is already a separate, already-stabilized unit on the DAG, the asset amount remains credited in the AA's `aa_balances` table (per `updateInitialAABalances`/`updateFinalAABalances`), but the AA's response logic has no other way to release it: any subsequent attempt to pay it out to the same (non-attested) address will hit the identical validation failure, and the AA typically has no alternate address to send to. This differs from a simple wallet, where a user can choose a different, attested destination address; an AA's oscript logic is fixed and, in typical "bounce/forward" patterns, always targets `trigger.address`.

### Impact Explanation
This satisfies the "AA fund loss or freezing" acceptance criterion. An unprivileged AA trigger sender who is not on a `spender_attested` asset's attestor list can cause tokens sent to (or forwarded through) the AA to become permanently stuck in the AA's balance with no automatic recovery path, because the protocol's bounce/return mechanism assumes it can always safely pay back to `trigger.address`, and does not first check whether that recipient is a valid destination for the asset in question (`spender_attested`, and analogously `cosigned_by_definer` or non-`is_transferrable` checks could also block a bounce-back).

### Likelihood Explanation
Reachable by any user with an address that (a) is not attested for a given `spender_attested` asset and (b) sends that asset to any AA whose oscript logic uses the default bounce mechanism or explicitly forwards funds back to `trigger.address`/`trigger.initial_address` (a very common oscript pattern, as shown by the "Forwarder of bytes" and "Just a bouncer" sample templates in the test suite [6](#0-5) [7](#0-6) ). No cooperation from the AA owner, witnesses, or the asset issuer is required; it only requires that the asset happens to be `spender_attested` and that the sender/trigger address is not attested, a state that is entirely realistic for restricted/regulated tokens issued on Ocore (the platform's designed analog of KYC-gated stablecoins).

### Recommendation
- In `bounce()`/`sendUnit()`, before attempting to pay a `spender_attested` (or otherwise transfer-restricted) asset back to `trigger.address`, check whether that address satisfies the asset's `transfer_condition`/attestation requirements (e.g., via `storage.filterAttestedAddresses`) and, if not, avoid consuming the funds silently—either keep them explicitly earmarked in the AA's balance with a clear non-silent failure state, or expose a getter/state variable so AA authors can detect and handle the stuck balance (e.g., allow forwarding to a different address).
- Alternatively, document prominently that oscript authors must not assume that "push back to trigger.address" is always safe for arbitrary custom assets, and provide official oscript library helpers that verify attestation before attempting a payment, following a pull-based release pattern (e.g., let the attested address later claim funds via a separate trigger) rather than unconditional push.

### Proof of Concept
1. An asset issuer defines an asset `A` with `spender_attested: true` and a small attestor list, per `validateAssetDefinition`/`checkAttestorList` [8](#0-7) .
2. Deploy an AA using the standard bounce/forwarder oscript pattern, e.g. `just_a_bouncer.oscript`, which simply forwards `trigger.output[[asset=base]] - fee` back to `trigger.address` [6](#0-5)  (a real-world AA using the equivalent forwarding pattern for asset `A` instead of base bytes would exhibit this).
3. An address `X` that is **not** in `A`'s attestor-approved list sends a trigger unit containing asset `A` to the AA. `updateInitialAABalances` credits `A` into the AA's balance for address `X`'s trigger output [2](#0-1) .
4. Suppose the AA's primary response formula fails (or, for a bouncer, is designed to trigger a bounce) — `bounce()` is invoked and attempts to compose a payment message sending asset `A` back to `X` [9](#0-8) .
5. `sendUnit()` -> `validateAndSaveUnit()` runs full unit validation; the `spender_attested` check in `validatePaymentInputsAndOutputs` rejects the output address `X` since it is not attested [1](#0-0) , producing an error that funnels back into `bounce(err)` [4](#0-3) .
6. Because `bBouncing` is already `true`, this second call to `bounce()` short-circuits to `finish(null)` [10](#0-9) , producing no response unit whatsoever. Asset `A` remains credited in the AA's `aa_balances` for that AA address but there is no code path in the AA's fixed oscript logic that can ever deliver it anywhere else, freezing it indefinitely.

**Uncertainty note:** I was not able to fully trace every downstream call path connecting `validateAndSaveUnit`'s failure back into the exact `bounce()` re-entry (some intermediate glue code in `aa_composer.js` around `revert()`/`finish()` was only partially visible in the indexed snippets), so the precise sequencing of the second `bounce()` call versus a `ROLLBACK TO SAVEPOINT` should be double-checked against the full source before treating this as fully confirmed. Given index size limits, some file contents may not be available; a full review of `aa_composer.js` in a Devin session (or direct repo access) is recommended to verify this call chain end-to-end.

### Citations

**File:** validation.js (L2630-2641)
```javascript
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
```

**File:** validation.js (L2745-2755)
```javascript
	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");

	// denominations
	if (payload.fixed_denominations && !isNonemptyArray(payload.denominations))
		return callback("denominations not defined");
	if (!payload.fixed_denominations && "denominations" in payload)
```

**File:** aa_composer.js (L474-490)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
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

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

**File:** test/samples/just_a_bouncer.oscript (L1-14)
```text
{
	bounce_fees: { base: 10000 },
	messages: [
		{
			app: 'payment',
			payload: {
				asset: 'base',
				outputs: [
					{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
				]
			}
		}
	]
}
```

**File:** test/ojson.test.js (L658-679)
```javascript
test('Forwarder of bytes', t => {
	var ojson = readSample('forwarder_of_bytes.oscript')
	parseOjson(ojson, (err, res) => { t.deepEqual(err || res,
		[
			"autonomous agent",
			{
				messages: [
					{
						if: '{trigger.output[[asset=base]] > 2000}',
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{ address: "PCEJIRXNA56T6VQOOSPV6GOJVLVN6AO6", amount: "{ trigger.output[[asset=base]] - 2000 }" }
							]
						}
					},
				]
			}
		]
	)});
});
```
