This confirms the finding: when an unprivileged sender's payment to an AA carries a fixed-denomination (indivisible) asset, `aa_composer.js` credits it to the AA's balance via `updateInitialAABalances` (`aa_composer.js:481-482`), but if the AA's own response logic tries to forward that same asset back out in a `payment` message, the message is silently dropped rather than causing a bounce or an error.

## Title
AA responses silently discard payments in fixed-denomination assets, permanently trapping unrecoverable funds - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `sendUnit()` function silently filters out any outgoing `payment` message whose asset is `fixed_denominations` (indivisible), instead of bouncing the trigger or erroring. Combined with the fact that the AA never has any built-in code path to build indivisible-asset payment messages (there is no "indivisible" output builder analogous to `completePaymentPayload` for divisible/base assets, and `validation.js` requires fixed-denomination payment messages to carry `denomination` and use single-input coin-matching semantics that the generic AA payload builder never produces), an AA is structurally unable to ever send out a fixed-denomination asset it received. This mirrors the Centrifuge bug class: a legitimate value-bearing operation ("send this asset back") is accepted by the outer validation layer but is silently zeroed/dropped internally instead of failing loudly or refunding, leaving the value stuck with no privileged or unprivileged recovery path at all (worse than Centrifuge, where at least an admin sweep exists).

### Finding Description
When a trigger unit sends an indivisible/fixed-denomination asset to an AA, the asset is credited to the AA's on-chain balance in `updateInitialAABalances`: [1](#0-0) 

Later, if the AA's own `messages` template tries to pay this same asset back out (e.g. as a refund/bounce/forward), `sendUnit()` looks up the asset and, upon seeing `fixed_denominations`, defers processing ("will skip it later") instead of composing inputs/outputs for it: [2](#0-1) 

In the second pass, any such message is unconditionally filtered out of the unit with no error raised: [3](#0-2) 

If that was the only payment message in the response, execution proceeds to a "successful" empty response (`no messages after removing fixed denominations`) rather than bouncing—i.e., there is no error surfaced to the trigger author, and the funds are quietly retained.

Unlike the base/divisible-asset path, which has a full input-selection and completion routine (`completePaymentPayload`, lines 1061‑1246) that builds a proper spendable payment (choosing UTXOs, computing change, etc.), there is no equivalent mechanism anywhere in `aa_composer.js` for constructing fixed-denomination payment messages (inputs must reference a single UTXO of matching denomination per `validation.js:2142` `"fixed denominations payment must have 1 input"`, and outputs must be denomination-aligned per `validation.js:2161`). The AA execution engine has no logic to pick a UTXO of the correct denomination from its own balance and build such an input/output pair. This means *any* attempt by an AA definition to forward, refund, or otherwise pay out an indivisible asset it received is a silent no-op, not merely in the batching-flag sense of the Centrifuge bug, but universally for this whole asset class.

### Impact Explanation
Any unprivileged user (or asset issuer) can send a fixed-denomination (`fixed_denominations: true`) asset to any Autonomous Agent, either directly or as an unwitting trigger payment intended to be forwarded/refunded by the AA's own oscript logic (a common bounce/refund/proxy pattern used throughout the sample AAs, e.g. `test/samples/fundraising_proxy.oscript`, `just_a_bouncer.oscript`). Because `sendUnit()` unconditionally drops fixed-denomination outgoing payment messages, those funds become permanently locked in the AA's `aa_balances` row with *no* code path—privileged or otherwise—to ever move them out again, since AA definitions cannot construct valid indivisible-asset payment messages through the composer at all. This is a permanent, unrecoverable freeze of user funds (asset supply lock), triggered by ordinary AA usage patterns, not by any malicious actor.

### Likelihood Explanation
High likelihood: this triggers on the normal/expected interaction pattern of sending any asset, including a fixed-denomination one, to an AA that is designed to forward, refund, or bounce received assets (a very common Oscript pattern seen across sample AAs). No special privilege or malicious intent is required—only that the asset happens to be `fixed_denominations` and the AA has logic that tries to pay it back out.

### Recommendation
In `sendUnit()`, when a `payment` message targets a `fixed_denominations` asset, the AA execution should bounce the trigger with an explicit error (e.g., "AAs cannot send fixed-denomination assets") rather than silently filtering the message and proceeding to a successful/empty response. This at least surfaces the failure so senders are warned and, more fundamentally, the protocol should either implement genuine indivisible-asset payment support for AAs or reject fixed-denomination asset payments to AA addresses at the validation layer (analogous to how private assets are already rejected outbound at `aa_composer.js:1329`).

### Proof of Concept
1. Issue an asset with `fixed_denominations: true` (indivisible/textcoin-style asset).
2. Deploy a bouncer/forwarder-style AA whose `messages` template pays the received asset back to `trigger.address`, mirroring the pattern in `test/samples/just_a_bouncer.oscript` but using `asset: "{trigger.output[[asset!=base]].asset}"` instead of `base`.
3. Send a payment output of that fixed-denomination asset to the AA address as a trigger.
4. Observe: `getTrigger()` records the received amount in `trigger.outputs[asset]`, `updateInitialAABalances` credits `aa_balances`, but `sendUnit()`'s filter at `aa_composer.js:1356` strips the outgoing payment message before the unit is built; the trigger completes "successfully" with `error_message = 'no messages after removing fixed denominations'` and the asset units are never returned to the sender, remaining stuck in `aa_balances` for that AA address indefinitely since no oscript payload construction path exists for indivisible outputs.

### Citations

**File:** aa_composer.js (L481-482)
```javascript
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
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

**File:** aa_composer.js (L1356-1361)
```javascript
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```
