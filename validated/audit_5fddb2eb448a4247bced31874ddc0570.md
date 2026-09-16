### Title
Private assets sent to an Autonomous Agent (AA) can never be released, permanently locking the deposit - ([File: aa_composer.js])

### Summary
An AA can receive any asset type—including private (non-transparent) assets—as part of a trigger's payment outputs, which are added to the AA's balance in `updateInitialAABalances`. However, `sendUnit`'s per-message payment processing explicitly refuses to let an AA send a private asset back out, unconditionally erroring with `"sending private asset from AA"`. Since this same code path is used both for the AA's normal response and for its bounce/refund logic, any private-asset deposit made to an AA can never be paid out by that AA under any code path, leaving the funds permanently stuck.

### Finding Description
When a trigger unit pays an asset to an AA address, `getTrigger` records the amount under `trigger.outputs[asset]` regardless of whether the asset is private or public. [1](#0-0) 

`updateInitialAABalances` then credits the AA's balance for that asset (public or private) unconditionally. [2](#0-1) 

When the AA subsequently tries to compose an outgoing payment message for that asset — whether it's part of a normal templated response or part of the automatic bounce/refund flow triggered by `bounce()` — `sendUnit`'s per-message loop looks up the asset info and, if `objAsset.is_private` is true, immediately fails the message with `"sending private asset from AA"`: [3](#0-2) 

This error propagates to the `async.eachSeries` completion callback, which calls `bounce(err)`: [4](#0-3) 

Critically, `bounce()` itself builds a refund message for every asset in `trigger.outputs` — including private ones — and calls `sendUnit(messages)` to send it: [5](#0-4) 

So if the *initial* response bounces (for any reason) and the AA tries to refund a private-asset deposit, `sendUnit` hits the same `"sending private asset from AA"` failure and calls `bounce()` a second time. The `bBouncing` guard then short-circuits into `finish(null)` with no response at all: [6](#0-5) 

The net effect: the private-asset amount was already added to the AA's balance (`aa_balances` table / `assocBalances`) during `updateInitialAABalances`, but there is no code path — normal response, refund, or bounce — by which the AA can ever construct a valid outgoing payment message carrying that private asset. The deposit is recorded as AA balance but can never leave the AA.

This mirrors the reported OpenQ issue structurally: a deposit type (NFT in OpenQ, private asset here) can be accepted into a fund-holding contract/AA, but the release code path unconditionally does not support that asset type, and the "refund" fallback path is subject to the exact same restriction, so once deposited the asset is permanently unrecoverable.

### Impact Explanation
Any user who (mistakenly or otherwise) sends a private asset payment to an AA address as part of a trigger unit will have those funds permanently locked in the AA. The AA's on-chain balance for that asset increases, but no combination of AA logic (state formulas issuing payments, or bounce-based refunds) can ever move a private asset out of an AA, since the restriction is enforced unconditionally in `sendUnit` regardless of trigger path (`bSecondary` or primary) or code branch (`bounce` vs. normal `messages`). This is a permanent, unrecoverable fund loss for the depositor with no admin/privileged override available in the composer logic itself.

### Likelihood Explanation
Likelihood is moderate: it requires a user (or a griefer targeting a specific AA, similar to the "malicious" deposit inducing scenario in the OpenQ report) to send a private-asset payment to an AA. Since ocore/Obyte supports private (non-public) assets as first-class payment types reachable by any unprivileged unit poster, and nothing in the trigger-acceptance path (`getTrigger`/`updateInitialAABalances`) rejects or bounces private-asset deposits at intake time, this can be triggered unintentionally by any user unfamiliar with this restriction, or intentionally to grief specific AAs that are expected to forward received assets.

### Recommendation
Reject private-asset deposits to AAs at intake time rather than accepting them into balance and later failing to release them. Specifically, in `updateInitialAABalances` / trigger-outputs handling, detect if `trigger.outputs` contains a private asset and immediately bounce the trigger unit's non-private (base) fees back while refusing to credit the AA's balance for the private asset, or otherwise ensure the deposited private-asset amount is fully and unconditionally returned to the sender as part of the very first `bounce()` invocation, before the `sendUnit`'s private-asset restriction can cause a second, silent, no-op bounce.

### Proof of Concept
1. Deploy an AA whose template has a response that, on any trigger, attempts (or is expected) to forward received assets or simply issues a state update without repaying a specific asset it received.
2. From an unprivileged account, send a trigger unit containing a `payment` message for a **private asset** (`is_private: true`) with output directed to the AA address, along with enough base bytes to cover `bounce_fees.base`.
3. `getTrigger` records the private asset amount in `trigger.outputs[asset]`; `updateInitialAABalances` credits `aa_balances` for that asset/address pair (visible in `aa_balances` table).
4. If the AA's template logic ever attempts to pay this asset back out (either intentionally in a response message, or via `bounce()` for any unrelated validation failure), `sendUnit`'s check `if (objAsset.is_private) return cb("sending private asset from AA")` fails the payment message.
5. This error causes `bounce(err)` to be invoked; since `bounce()` also constructs a payment message for the same private asset (from `trigger.outputs`), it calls `sendUnit` again, which fails identically; the `bBouncing` guard causes `finish(null)` — no response unit is produced, and the asset balance remains permanently credited to the AA with no path to withdraw it.

### Citations

**File:** aa_composer.js (L382-393)
```javascript
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
```

**File:** aa_composer.js (L481-490)
```javascript
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

**File:** aa_composer.js (L909-929)
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
```

**File:** aa_composer.js (L930-944)
```javascript
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
```

**File:** aa_composer.js (L1323-1331)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
```

**File:** aa_composer.js (L1346-1349)
```javascript
			function (err) {
				if (err)
					return bounce(err);
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
```
