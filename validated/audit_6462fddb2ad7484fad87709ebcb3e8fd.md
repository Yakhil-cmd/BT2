## Analysis Result

### Title
AA responses silently drop payment messages for indivisible (fixed-denomination/NFT-like) assets while committing state changes, permanently freezing those assets in the AA - (File: aa_composer.js)

### Summary
The reported bug class is: a claim/completion flow updates internal accounting for one asset type (ERC20) but silently fails to release a second asset type (NFT) that was supposed to accompany it, permanently trapping the NFT. Obyte's AA (Autonomous Agent) engine has a structurally identical flaw: any `payment` message an AA response wants to send in a `fixed_denominations` asset (ocore's non-fungible/indivisible-coin equivalent of an NFT) is silently removed from the outgoing unit with no error and no bounce, while any accompanying state-variable writes in the same response (e.g. marking a claim/bounty/order as "paid"/"released") are still committed.

### Finding Description
When an AA response is composed in `sendUnit`, each payment message is inspected per-asset. If the asset is `fixed_denominations` (an indivisible asset, the closest ocore analog to an NFT because it is issued/held/transferred as discrete non-fungible coins), the code explicitly skips building input/output data for it with a bare `return cb();` and the comment "will skip it later": [1](#0-0) 

Later, after this same `async.eachSeries` pass, the composer performs a second filtering pass that unconditionally strips out *any* payment message referencing a `fixed_denominations` asset from the final message list, with only a `console.log` if this empties the whole message set: [2](#0-1) 

Crucially, this filtering happens only on `payment`-app messages. It does not affect other messages in the same AA response, in particular `state` messages that already ran as part of `evaluateAA`, which is invoked before `sendUnit` and produces `template.messages` together with the state-variable side effects: [3](#0-2) 

So if an AA author writes a bounty/claim/ongoing-payout style AA that, in one trigger response, both (a) writes a state variable marking a task/bounty/order as completed/released and (b) sends a payment message for a `fixed_denominations` asset (the NFT-equivalent reward) to the claimer, the "mark as done" state change is committed together with the response unit, but the NFT payment message is quietly dropped without any bounce or error message returned to the caller. The AA's balance for that indivisible asset is never debited to the recipient — the asset silently remains parked at the AA address, and because the state already flags the claim as processed, most contract logic (mirroring the bounty pattern in the report) has no path left to re-trigger the payout.

### Impact Explanation
This causes concrete AA fund loss/freezing: an indivisible (NFT-like) asset balance held by the AA becomes permanently stuck at the AA's address, unrecoverable by the intended recipient, while the AA's own accounting (state vars, `response`, other released asset such as base bytes or a divisible token) proceeds as if the full payout succeeded. This matches the "AA fund loss or freezing" acceptance criterion — a legitimate unprivileged trigger sender who completes all preconditions still permanently loses the NFT-equivalent reward with no error surfaced.

### Likelihood Explanation
Likelihood is high for any AA design that combines fungible and non-fungible (fixed-denomination) asset payouts in a single trigger branch — a common and natural pattern for auction/bounty/marketplace/loyalty AAs modeled after the reported bounty use case. No special privileges are needed: any address can send a normal trigger unit that satisfies the AA's `if` condition; the bug is triggered purely by the AA's own message composition once conditions are met, and it happens deterministically and silently (no bounce, no explicit error) every time such a message reaches this code path.

### Recommendation
In `aa_composer.js`, when a payment message specifies a `fixed_denominations` asset, `sendUnit` should `bounce()` the response (as is already done for `is_private` assets at line 1329-1330) instead of silently dropping the message at the filtering step, so AA authors get an explicit, deterministic failure rather than a partially-executed response that leaves the indivisible asset stranded. Alternatively, add real support for AAs to programmatically construct fixed-denomination outputs (matching `denomination`/serial number semantics of `indivisible_asset.js`) so such payouts can actually succeed.

### Proof of Concept
1. Issue an indivisible/fixed-denomination asset `X` (the NFT-equivalent) and fund an AA address with a unit of `X`.
2. Deploy an AA whose response, on a matching trigger, contains two messages: a `state` message that sets `var['claimed_' || trigger.unit] = 1` and a `payment` message sending asset `X` to `trigger.address`.
3. Any user sends a valid trigger unit that satisfies the branch's `if` condition (analogous to "user completes the task").
4. `handleTrigger` → `evaluateAA` executes the state formula, and `sendUnit` is invoked with both messages; per `aa_composer.js:1323-1330` and `1356-1361`, the `payment` message for `X` is stripped without error, while the `state` write persists as part of the committed response unit.
5. Result: `var['claimed_...']` is `1` (claim marked done) but the AA's balance of asset `X` is unchanged and the intended recipient never receives it — the asset is permanently frozen at the AA address.

### Citations

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

**File:** aa_composer.js (L1865-1886)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
			var messages = template.messages;
			if (!messages)
				return bounce('no messages');
			// this will also filter out the special message that performs the state changes
			messages = messages.filter(function (message) { return (isNonemptyObject(message) && 'payload' in message && (message.app !== 'payment' || isNonemptyObject(message.payload) && Array.isArray(message.payload.outputs))); });
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
			messages.forEach(function (message) {
				var payload = message.payload;
				if (message.app === 'asset' && isNonemptyArray(payload.denominations) && payload.denominations.every(d => isNonemptyObject(d) && ValidationUtils.isPositiveInteger(d.denomination)))
					payload.denominations.sort(sortDenominations);
				if ((message.app === 'asset' || message.app === 'asset_attestors') && isNonemptyArray(payload.attestors) && payload.attestors.every(ValidationUtils.isValidAddress))
					payload.attestors.sort();
			});
			sendUnit(messages);
		});
```
