## Title
AA response with multiple payment messages bounces entirely (freezing all bundled payouts) when any single bundled asset is incompatible with AA sending semantics - (File: aa_composer.js)

## Summary
The Sherlock report describes `ClaimManagerV1` iterating over all bounty tokens and sending them one-by-one; a single attacker-funded token that reverts on transfer blocks the whole loop and freezes legitimate claim payouts for every other (valid) token in the same bounty. The analogous bug class in ocore is in the AA response-composer's `sendUnit()` message loop: when an AA response bundles several `payment` messages (e.g. paying out multiple assets that were deposited into the AA), the code processes them with `async.eachSeries` and treats a single failure on *any one* asset as fatal to the *entire* response, via `return bounce(err)`. An unprivileged user can deposit/trigger with an asset that is guaranteed to fail this per-message check (most simply, a private asset), and if that asset payment ever ends up bundled together with other legitimate outputs in the same AA response, the whole response — including the legitimate byte/asset payouts to other parties — is bounced and its state changes and balance updates are rolled back.

## Finding Description
In `aa_composer.js`, `sendUnit()` iterates over the AA's outgoing `messages` (payment messages, one per asset) using `async.eachSeries`, resolving each asset via `storage.loadAssetWithListOfAttestedAuthors` and calling `completePaymentPayload`: [1](#0-0) 

If any single asset in the batch fails this per-message processing — for example a **private asset**, which is unconditionally rejected with `"sending private asset from AA"` because private-asset spend proofs cannot be attached by an AA — the error is propagated to the batch completion handler: [2](#0-1) 

which calls `bounce(err)` for the *whole* unit, not just the offending message: [3](#0-2) 

`bounce()` restores balances/state variables to their pre-trigger snapshot and (for non-air runs) issues `ROLLBACK TO SAVEPOINT initial_balances`, discarding *all* pending outputs bundled in that response — not only the failing asset's payment: [4](#0-3) 

Funding/depositing into an AA is permissionless: any unit poster can send any asset (including a newly-defined private asset) to an AA address as part of a trigger. `validatePayment` in `validation.js` confirms private assets are validated normally as deposits (subject only to `asset privacy mismatch` checks against the message's own privacy flag), so an attacker can freely deposit a private asset into a shared/pooled AA: [5](#0-4) 

This is structurally identical to the Solidity bug: a loop over multiple "tokens/assets" to be paid out where a single incompatible one (attacker-supplied) causes the entire batch operation to fail atomically, rather than being isolated or skipped, freezing payouts to unrelated, legitimate recipients bundled in the same operation.

## Impact Explanation
Any AA design that pools/bundles multiple assets deposited by different users and pays them out together in one response (a common pattern for bounty/reward/crowdfunding-style AAs, directly analogous to the OpenQ bounty contract) can be permanently frozen by an attacker depositing one incompatible asset (e.g., a private asset) into the pool. Every time the AA attempts to compose and send its bundled response, the per-message loop hits the poisoned asset, `bounce()` fires, and the entire batch (including legitimate winners'/depositors' payouts) is rolled back and never delivered — a concrete AA fund-freezing condition reachable by an ordinary trigger sender.

## Likelihood Explanation
Depositing assets to an AA and triggering it is entirely permissionless — no special privilege is required, matching the "attacker can fund with an invalid token" precondition in the original report. Defining a private asset and sending it into a bounty-like AA is straightforward and deterministic (the `is_private` check in `sendUnit` always fails for any AA attempting to send it), so the freeze is guaranteed to trigger whenever the AA's own payout logic bundles that asset with other outputs.

## Recommendation
When composing a multi-message AA response, isolate the failure of an individual asset's payment (e.g., an asset that cannot legally be sent by an AA, such as a private asset, or one requiring issuance the AA cannot perform) instead of bouncing the entire unit. Either allow the affected message to be dropped independently while still processing/sending the remaining valid payment messages, or fail earlier/synchronously during evaluation so AA authors can explicitly branch away from including an unsendable asset, rather than having a single bad asset silently doom an entire batched response including unrelated recipients' funds. At minimum, document this all-or-nothing bounce semantics clearly so AA authors avoid bundling untrusted/attacker-controllable assets together with other parties' guaranteed payouts in a single response.

## Proof of Concept
1. Attacker sends a unit that defines a new private asset `X` (`is_private: true`, satisfying validity rules in `validateAssetDefinition`).
2. Attacker sends a trigger unit to a bounty/pool-style AA that deposits asset `X` alongside base bytes, following whatever deposit interface the AA exposes (analogous to `DepositManagerV1.fundBountyToken` being permissionless).
3. When the AA's payout logic later composes a response bundling a payment of asset `X` back to depositors together with a base-currency (or other token) payment to the legitimate winner/claimant, `sendUnit()`'s `async.eachSeries` loop hits asset `X`, and `loadAssetWithListOfAttestedAuthors`/message processing returns `"sending private asset from AA"`. [6](#0-5) 
4. `bounce(err)` is invoked, rolling back all state changes and balances for that response — the legitimate winner's payment (bundled in the same messages array) is never sent, and every subsequent identical trigger reproduces the same bounce, permanently freezing the payout. [7](#0-6)

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

**File:** aa_composer.js (L1298-1330)
```javascript
		async.eachSeries(
			messages,
			function (message, cb) {
				if (message.app !== 'payment') {
					try {
						if (message.app === 'definition')
							message.payload.address = objectHash.getChash160(message.payload.definition);
						completeMessage(message);
					}
					catch (e) { // may error if there are empty objects or arrays inside
						return cb("some hashes failed: " + e.toString());
					}
					return cb();
				}
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1346-1350)
```javascript
			function (err) {
				if (err)
					return bounce(err);
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
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

**File:** validation.js (L2093-2098)
```javascript
		else{
			if ("denomination" in payload)
				return callback("denomination in arbitrary-amounts asset")
		}
		if (!!objAsset.is_private !== !!objValidationState.bPrivate)
			return callback("asset privacy mismatch");
```
