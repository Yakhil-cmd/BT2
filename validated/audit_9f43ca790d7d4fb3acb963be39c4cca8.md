### Title
Premature, un-rollback-able consumption of a capped indivisible asset's one-time issuance slot before payment signing completes, permanently freezing the asset supply - ([File: indivisible_asset.js])

### Summary
`pickIndivisibleCoinsForAmount()`'s `issueNextCoin()` helper reserves a capped, indivisible asset's *only* issuance slot by unconditionally executing `UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 ...` as soon as it decides to mint a coin, before the unit that would actually carry that issuance is signed or broadcast. This update runs on the same DB connection that `composer.composeJoint()` commits **before** authors sign the unit, so if signing subsequently fails for any reason, the reservation is permanently persisted with no unit ever created to consume it — analogous to coturn marking the odd sibling port `TPS_TAKEN_ODD` without any code path that will ever release it.

### Finding Description
For a capped asset (`objAsset.cap` set), the issuance query restricts eligible denomination rows with `can_issue_condition = "max_issued_serial_number=0"`, i.e. the entire capped supply may be issued exactly once: [1](#0-0) 

As soon as a matching denomination is found, `issueNextCoin()` immediately increments `max_issued_serial_number` in the database, *before* the payment message, signatures, or the final unit hash are produced: [2](#0-1) 

This happens inside `retrieveMessages`, which `composer.composeJoint()` invokes on the same `conn` that is used for the rest of unit composition: [3](#0-2) 

Critically, `composeJoint()` commits this transaction — and therefore the `asset_denominations` update — **before** the authors actually sign the unit: [4](#0-3) 

Signing happens afterward, and it can fail for ordinary reasons that are entirely outside of validation/consensus, e.g. a cosigner on a multisig/shared address refusing to sign, or a remote signer/device error: [5](#0-4) 

When signing fails, `handleError()`/`ifNotEnoughFunds`/`ifError` are invoked and no joint is ever produced or broadcast — but the `max_issued_serial_number` increment that was already committed is never rolled back, because the commit already happened prior to the point of failure. Once `max_issued_serial_number` is nonzero, `can_issue_condition = "max_issued_serial_number=0"` can never match again for that capped asset, so `issueNextCoin()` will return `NOT_ENOUGH_FUNDS_ERROR_MESSAGE` on every future attempt: [6](#0-5) 

The asset's entire fixed supply is thus permanently unmintable — the coturn analog of marking `TPS_TAKEN_ODD` for a port that will never be released, exhausting the (one-shot) issuance pool for good.

### Impact Explanation
The asset definer (an authorized "asset issuer", one of the explicitly in-scope actors) who composes the single allowed issuance of a capped, indivisible, private or shared/multisig-controlled asset can permanently and irrecoverably lose the ability to mint any of that asset's supply if the signing step fails after the reservation is committed (a cosigner declining, a disconnected signing device, a network/timeout error talking to a remote signer, etc.). This is a genuine, permanent freezing of asset issuance functionality/supply with no remediation path, matching the "asset issuance and transfer conditions" and "AA/asset fund loss or freezing" categories called out as in-scope.

### Likelihood Explanation
Reaching this state requires only: (1) defining a capped, `fixed_denominations` (indivisible) asset, and (2) attempting to issue it from a multi-author/shared address or via any signer that can fail after the transaction commits (a routine, easily reproduced condition — a cosigner simply has to decline once, or a hardware/remote signer connection can drop). No malicious peer, node, or network condition is required; a normal wallet operation combined with an ordinary signing failure suffices, and the outcome (an asset that can never be issued) is deterministic and irreversible once triggered.

### Recommendation
Do not commit the `asset_denominations` reservation (`UPDATE ... max_issued_serial_number=max_issued_serial_number+1`) until the unit is fully signed and confirmed for broadcast. Either move the increment to occur only in the actual `writer.js` save path (after a valid, signed unit exists), or keep the reservation in the same transaction that is only committed after successful signing, with a compensating rollback/decrement path if signing fails before the joint is finalized.

### Proof of Concept
1. Definer creates a capped, `fixed_denominations: true` asset owned by a 2-of-2 shared (multisig) address.
2. Definer calls `composeIndivisibleAssetPaymentJoint()` to issue the capped supply to some address. `pickIndivisibleCoinsForAmount()` → `issueNextCoin()` runs `UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 ...` and the enclosing `composeJoint()` transaction is `COMMIT`ed at [7](#0-6)  before signatures are collected.
3. During the subsequent signing step, the second cosigner refuses to sign (or the signing device disconnects), producing the error at [8](#0-7) ; `params.callbacks.ifError`/`ifNotEnoughFunds` fires and no unit is ever created or broadcast.
4. Any further attempt to issue the same capped asset now returns `NOT_ENOUGH_FUNDS_ERROR_MESSAGE` from `issueNextCoin()`/`pickIndivisibleCoinsForAmount()` because `max_issued_serial_number` is already nonzero, permanently preventing the asset's supply from ever being minted.

### Citations

**File:** indivisible_asset.js (L516-545)
```javascript
		function issueNextCoin(remaining_amount){
			console.log("issuing a new coin");
			if (remaining_amount <= 0)
				throw Error("remaining amount is "+remaining_amount);
			var issuer_address = objAsset.issued_by_definer_only ? objAsset.definer_address : arrAddresses[0];
			var can_issue_condition = objAsset.cap ? "max_issued_serial_number=0" : "1";
			conn.query(
				"SELECT denomination, count_coins, max_issued_serial_number FROM asset_denominations \n\
				WHERE asset=? AND "+can_issue_condition+" AND denomination<=? \n\
				ORDER BY denomination DESC LIMIT 1", 
				[asset, remaining_amount+tolerance_plus], 
				function(rows){
					if (rows.length === 0)
						return onDone(NOT_ENOUGH_FUNDS_ERROR_MESSAGE);
					var row = rows[0];
					if (!!row.count_coins !== !!objAsset.cap)
						throw Error("invalid asset cap and count_coins");
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
					conn.query(
						"UPDATE asset_denominations SET max_issued_serial_number=max_issued_serial_number+1 WHERE denomination=? AND asset=?", 
						[denomination, asset], 
						function(){
							var input = {
								type: 'issue',
								serial_number: serial_number,
								amount: issue_amount
							};
```

**File:** composer.js (L456-470)
```javascript
		function(cb){
			if (!fnRetrieveMessages)
				return cb();
			console.log("will retrieve messages");
			fnRetrieveMessages(conn, last_ball_mci, bMultiAuthored, arrPayingAddresses, function(err, arrMoreMessages, assocMorePrivatePayloads){
				console.log("fnRetrieveMessages callback: err code = "+(err ? err.error_code : ""));
				if (err)
					return cb((typeof err === "string") ? ("unable to add additional messages: "+err) : err);
				Array.prototype.push.apply(objUnit.messages, arrMoreMessages);
				if (assocMorePrivatePayloads && Object.keys(assocMorePrivatePayloads).length > 0)
					for (var payload_hash in assocMorePrivatePayloads)
						assocPrivatePayloads[payload_hash] = assocMorePrivatePayloads[payload_hash];
				cb();
			});
		},
```

**File:** composer.js (L530-536)
```javascript
		// we close the transaction and release the connection before signing as multisig signing may take very very long
		// however we still keep c-ADDRESS lock to avoid creating accidental doublespends
		conn.query(err ? "ROLLBACK" : "COMMIT", function(){
			conn.release();
			if (err)
				return handleError(err);
			
```

**File:** composer.js (L561-579)
```javascript
							if (signer.sign){
								signer.sign(objUnit, assocPrivatePayloads, address, path, function(err, signature){
									if (err)
										return cb3(err);
									// it can't be accidentally confused with real signature as there are no [ and ] in base64 alphabet
									if (signature === '[refused]')
										return cb3('one of the cosigners refused to sign');
									author.authentifiers[path] = signature;
									cb3();
								});
							}
							else{
								signer.readPrivateKey(address, path, function(err, privKey){
									if (err)
										return cb3(err);
									author.authentifiers[path] = ecdsaSig.sign(text_to_sign, privKey);
									cb3();
								});
							}
```
