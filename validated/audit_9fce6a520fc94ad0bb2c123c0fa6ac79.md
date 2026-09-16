### Title
AA responses unconditionally reject any private-asset payment message, permanently freezing private-asset funds sent to an AA - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `sendUnit()` function, which composes the response unit an AA sends back after processing a trigger, contains a hard-coded rejection of any outgoing payment message that references a private asset. This mirrors the reported ERC1155 bug pattern: a code path that is expected to support a general operation (arbitrary asset payment) unconditionally fails for one legitimate sub-case (private assets), regardless of AA logic or balances.

### Finding Description
When an AA composes its response messages in `sendUnit()`, it iterates over all non-base payment messages and loads the referenced asset. If the asset `is_private`, the code always bails out with an error instead of attempting to build the payment: [1](#0-0) 

```js
storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
    if (err)
        return cb(err);
    assetInfos[asset] = objAsset;
    if (objAsset.fixed_denominations) // will skip it later
        return cb();
    if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
        return cb("sending private asset from AA");
```

This `cb(...)` propagates as an error into the `async.eachSeries` completion handler, which calls `bounce(err)`: [2](#0-1) 

`bounce()` only ever returns the base-asset (bytes) balance associated with the trigger, minus `bounce_fees`; it has no mechanism to return any asset other than `base`: [3](#0-2) 

Nothing in AA definition validation (`aa_validation.js`) or trigger validation (`validation.js` `validateAATrigger`) prevents a private asset from being sent as a trigger payment to an AA address, nor does it prevent an AA author from writing oscript logic (e.g., a refund/forward case, as seen in patterns like the "refund" case in `test/samples/fundraising_proxy.oscript`) that attempts to pay out a private asset it holds. The general payment validation path (`validatePayment` in `validation.js`) treats private and public assets symmetrically with regard to transfer/issue conditions and definer checks, with no special-case exclusion for AA senders: [4](#0-3) 

Thus an AA can legitimately accumulate a balance of a private asset (any sender can pay a private asset to an AA address just like any other output), but the AA's own execution engine can *never* successfully construct a unit that pays that private asset back out — every attempt unconditionally fails with `"sending private asset from AA"`, and the fallback bounce mechanism only ever refunds bytes, not the private asset itself.

### Impact Explanation
Any private asset balance accumulated by an AA becomes permanently unspendable/unrecoverable by that AA. Since the AA is the sole entity authorized to move funds it controls (per the "this address" ownership model of ocore), and its only mechanism for emitting payments (`sendUnit`) unconditionally refuses private-asset outputs, there is no path — bounce or success — by which the AA can ever release that private asset again. This is a concrete freezing of AA-held funds, which is explicitly an accepted impact category (AA fund loss or freezing). Any AA whose designed logic includes forwarding, refunding, or exchanging a private asset held in its balance (a pattern the oscript language and templates otherwise fully support, as private assets are a first-class asset type) is silently broken: users who send a private asset to such an AA lose access to it permanently, with no compensating bounce of the private asset (only unrelated bytes bounce fees are refunded, and even that only if separately paid).

### Likelihood Explanation
This is trivially reachable by any unprivileged party: simply send a private-asset payment to an AA address (a normal `payment` message, permitted by `validatePayment`), where the AA's definition happens to include logic that would otherwise pay out that asset (e.g. a swap/refund AA). The very first attempt by the AA to emit that payment message deterministically fails every time — this is not a race condition or edge case, it is a hard-coded, unconditional rejection with 100% reproducibility.

### Recommendation
Either (a) prevent private assets from being sent to AA addresses at the protocol/validation level (rejecting such trigger payments outright, so users are never misled into believing an AA can custody/process private assets), or (b) implement genuine support for constructing private-asset payment messages from an AA (generating the necessary `spend_proofs`/private element chains), or (c) at minimum ensure the bounce mechanism can refund the specific private asset that triggered the failure, rather than only ever refunding the base asset, so that private-asset funds sent to an AA are never irrecoverably stuck.

### Proof of Concept
1. Deploy an AA whose `messages` template includes a `case` that pays out an asset the AA is expected to hold, e.g. a "refund" branch:
```
{
  if: "{trigger.output[[asset=$asset]] > 0}",
  messages: [
    { app: 'payment', payload: { asset: "{$asset}", outputs: [{address: "{trigger.address}", amount: "{...}"}] } }
  ]
}
```
2. Have `$asset` resolve to a private asset (defined with `is_private: true`, `fixed_denominations: true`, `auto_destroy: false`, `is_transferrable: false` per the constraints in `validateAssetDefinition`, see [5](#0-4) ).
3. Send a private-asset payment of that asset to the AA's address as a trigger (permitted per `validatePayment`, `validation.js:2060-2124`).
4. Observe that when the AA attempts to execute the refund branch, `sendUnit()` in `aa_composer.js` (lines 1323-1330) rejects the message with `"sending private asset from AA"`, `bounce()` is invoked, and only the bytes bounce fee (if any) is refunded — the private asset amount remains stuck forever in the AA's balance with no future code path able to release it.

### Citations

**File:** aa_composer.js (L909-944)
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

**File:** aa_composer.js (L1346-1349)
```javascript
			function (err) {
				if (err)
					return bounce(err);
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
```

**File:** validation.js (L2059-2124)
```javascript
// used for both public and private payments
function validatePayment(conn, payload, message_index, objUnit, objValidationState, callback){

	if (!isNonemptyObject(payload))
		return callback("payment must be a non-empty object");
	if (!isNonemptyArray(payload.inputs))
		return callback("no inputs");
	if (!isNonemptyArray(payload.outputs))
		return callback("no outputs");

	if (!("asset" in payload)){ // base currency
		if (hasFieldsExcept(payload, ["inputs", "outputs"]))
			return callback("unknown fields in payment message");
		if (objValidationState.bHasBasePayment)
			return callback("can have only one base payment");
		objValidationState.bHasBasePayment = true;
		return validatePaymentInputsAndOutputs(conn, payload, null, message_index, objUnit, objValidationState, callback);
	}
	
	// asset
	if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callback("invalid asset");
	
	var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
	// note that light clients cannot check attestations
	storage.loadAssetWithListOfAttestedAuthors(conn, payload.asset, objValidationState.last_ball_mci, arrAuthorAddresses, objValidationState.bAA, function(err, objAsset){
		if (err)
			return callback(err);
		if (hasFieldsExcept(payload, ["inputs", "outputs", "asset", "denomination"]))
			return callback("unknown fields in payment message");
		if (objAsset.fixed_denominations){
			if (!isPositiveInteger(payload.denomination))
				return callback("no denomination");
		}
		else{
			if ("denomination" in payload)
				return callback("denomination in arbitrary-amounts asset")
		}
		if (!!objAsset.is_private !== !!objValidationState.bPrivate)
			return callback("asset privacy mismatch");
		var bIssue = (payload.inputs[0].type === "issue");
		var issuer_address;
		if (bIssue){
			if (arrAuthorAddresses.length === 1)
				issuer_address = arrAuthorAddresses[0];
			else{
				issuer_address = payload.inputs[0].address;
				if (arrAuthorAddresses.indexOf(issuer_address) === -1)
					return callback("issuer not among authors");
			}
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
			return callback("must be cosigned by definer");
		
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
		validatePaymentInputsAndOutputs(conn, payload, objAsset, message_index, objUnit, objValidationState, callback);
	});
```

**File:** validation.js (L2794-2801)
```javascript
	if (payload.is_private && payload.is_transferrable && !payload.fixed_denominations)
		return callback("if private and transferrable, must have fixed denominations");
	if (payload.is_private && !payload.fixed_denominations){
		if (!(payload.auto_destroy && !payload.is_transferrable))
			return callback("if private and divisible, must also be auto-destroy and non-transferrable");
	}
	if (payload.is_private && ("issue_condition" in payload || "transfer_condition" in payload) && (objValidationState.last_ball_mci >= constants.noPrivateAssetsWithConditionsUpgradeMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.noPrivateAssetsWithConditionsUpgradeMci))
		return callback("if private, cannot have issue or transfer conditions");
```
