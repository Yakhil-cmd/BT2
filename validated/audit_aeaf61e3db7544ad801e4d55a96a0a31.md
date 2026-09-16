### Title
Underfunding a single asset in an AA's `bounce_fees` causes complete forfeiture of *all* other assets (including base bytes) sent in the same trigger - (File: aa_composer.js)

### Summary
When a trigger unit sends multiple assets (base bytes plus one or more custom assets) to an Autonomous Agent (AA) and the AA's definition declares `bounce_fees` for one of those assets, underpaying the fee for *any single asset* causes the AA's `bounce()` routine to abort entirely, forfeiting the *entire* trigger payment — including base bytes that vastly exceed the required bounce fee — with no refund at all. This mirrors the reported Optimism bug class: a single underpaid fee-like parameter provided alongside a transfer causes irrecoverable loss of funds that would otherwise have been safely refundable.

### Finding Description
`handleTrigger` computes `bounce_fees` from the AA's definition (defaulting to `{base: constants.MIN_BYTES_BOUNCE_FEE}`), and before evaluating the AA it verifies the primary trigger meets the *base* bounce fee [1](#0-0) . However, the actual refund logic lives in `bounce()`: [2](#0-1) 

The loop iterates over every asset present in `trigger.outputs` (not just the one that caused the bounce). If **any** asset's received amount is smaller than its configured `bounce_fees[asset]` (`fee > amount`), the function immediately calls `finish(null)` — abandoning the refund process for **all** assets in the trigger, not just the underfunded one. Because `finish(null)` returns without composing or sending any response unit, none of the received value (base bytes or other assets) is ever sent back to `trigger.address`; the AA silently keeps everything.

This is architecturally the same failure mode as the Optimism issue: a fee-like precondition (`bounce_fees[asset]`) that the sender must satisfy for a specific sub-component of the transfer, when underpaid, causes total, irrecoverable loss of unrelated value that was otherwise sufficient and refundable (the base-byte bounce fee check on line 928 already passed).

The wallet-level guard `checkAAOutputs` in `aa_addresses.js` attempts to pre-validate outgoing payments against an AA's declared `bounce_fees` before sending [3](#0-2) , but this check is only invoked from the wallet's `sendMultiPayment` flow [4](#0-3) . It does not protect:
- AA-to-AA payments composed inside `handleTrigger`/`sendUnit`, where an AA's own `messages` template can send a multi-asset payment to a *second* AA address without any bounce-fee sufficiency check, since `sendUnit` only completes payload payloads and does not consult `checkAAOutputs` [5](#0-4) .
- Any composer/API path that does not explicitly call `checkAAOutputs` before submitting a unit (e.g., raw `composer.composeJoint` usage, custom bots, or hub-relayed light payments assembled by non-wallet code).

### Impact Explanation
A user or an intermediate AA that sends a trigger containing large amounts of base bytes together with a smaller amount of a secondary asset that falls short of an AA's per-asset `bounce_fees` requirement will lose the *entire* payment — not just the shortfall — because `bounce()` refuses to send back even the assets that were sufficiently funded. Since `bounce_fees` per asset is set arbitrarily by each AA author and is not required to be small or obvious, and since the check protecting against this (`checkAAOutputs`) is not universally enforced across every code path that can produce a trigger to an AA (particularly AA-to-AA composed payments in `sendUnit`), funds can be permanently and unrecoverably absorbed by the receiving AA with no path to reimbursement. This constitutes concrete, irreversible loss of user/AA funds.

### Likelihood Explanation
This can be triggered by any ordinary sender or by any AA definition whose own `messages` template pays a receiving AA in multiple assets — no privileged access or malicious peer is required. It requires only that the sender/paying AA under-supplies one asset relative to the receiving AA's declared `bounce_fees` for that asset while over-supplying bytes, a plausible and easy mistake given `bounce_fees` are set per-AA and not surfaced consistently outside the wallet UI. AA-composed payments (`sendUnit`) never run the `checkAAOutputs` safety check at all, making this reachable purely from oscript logic without any wallet-side protection.

### Recommendation
Change `bounce()` so that a shortfall in one asset's bounce fee does not forfeit refunds for other, sufficiently-funded assets: refund every asset that meets its own bounce-fee requirement, and only forfeit (or otherwise handle) the specific asset that is underfunded. Additionally, apply the equivalent of `checkAAOutputs`'s bounce-fee sufficiency validation to AA-generated payments in `sendUnit`/`handleTrigger` when an AA sends funds to another AA address, so that AA-to-AA transfers cannot silently strand funds either.

### Proof of Concept
1. Deploy AA `B` with `bounce_fees: { base: 10000, ASSET_X: 5000 }` and a `messages` template that only executes (and thus only refunds) when some unrelated condition holds (e.g., `trigger.data.someFlag`).
2. Send a trigger unit to `B` with `outputs: { base: 1000000 }` (well above `10000`) and a `payment` message transferring `1000` of `ASSET_X` (below the `5000` requirement) to `B`, without setting `someFlag`.
3. AA evaluation reaches the bounce-fee check loop; because `ASSET_X`'s amount (1000) is less than its `bounce_fees` (5000), `bounce()` hits `fee > amount` for `ASSET_X` and calls `finish(null)` before any payment message is created.
4. Result: none of the 1,000,000 bytes nor the 1,000 units of `ASSET_X` are refunded to the sender, even though the base-byte bounce fee was satisfied 100x over — the entire trigger value is absorbed by AA `B` with no recourse for the sender.

### Citations

**File:** aa_composer.js (L928-944)
```javascript
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
```

**File:** aa_composer.js (L1298-1344)
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
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
```

**File:** aa_composer.js (L1851-1859)
```javascript
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```

**File:** aa_addresses.js (L120-155)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (err, rows) {
		if (err)
			return handleResult(err);
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
```

**File:** wallet.js (L2186-2193)
```javascript
	if (!opts.aa_addresses_checked) {
		aa_addresses.checkAAOutputs(arrPayments, function (err) {
			if (err)
				return handleResult(err);
			opts.aa_addresses_checked = true;
			sendMultiPayment(opts, handleResult);
		});
		return;
```
