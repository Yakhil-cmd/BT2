## Confirmed: `checkAAOutputs` only validates bounce fees — it has no check that would reject a private-asset payment sent to an AA address. Combined with the explicit refusal in `aa_composer.js` to have an AA send private assets (`"it'll fail validation anyway due to lack of spend_proofs"`), this establishes the analog.

### Title
Missing Handling of Private Assets Sent to Autonomous Agents Causes Permanent Fund Freezing - (File: aa_composer.js, storage.js)

### Summary
The external report describes a Medium-severity design flaw where a contract could receive an asset (ETH) that its logic had no way to convert/unwrap, so the funds became unusable until a fix (`unwrapWETH`) was added. Ocore's Autonomous Agents (AAs) have an analogous, unremediated design gap: an AA can be paid in a **private asset**, but an AA can never track that balance, react to it in a trigger, or send it back out, because (a) private outputs are explicitly excluded when AA balances are computed, and (b) the AA composer explicitly refuses to build any payment message that spends a private asset from an AA. There is no "unwrapping"/conversion or rejection mechanism, so private-asset payments to an AA are permanently stuck.

### Finding Description
1. When an AA is triggered, or when balances are initially seeded for an AA, only public asset outputs are counted:
`storage.js` builds `aa_balances` with an explicit filter `AND (is_private=0 OR is_private IS NULL)` [1](#0-0) , and the balance-consistency check `checkBalances()` uses the identical filter [2](#0-1) . This means any private-asset output sent to an AA address is never reflected in `balance[asset]` inside the AA's oscript execution context — the AA logic literally cannot see it and therefore cannot decide to refund or process it.

2. Even if an AA's logic somehow attempted to send that asset out (e.g., a hard-coded response, or logic unaware of the restriction), `sendUnit()` in `aa_composer.js` explicitly bounces the response:
```
if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
    return cb("sending private asset from AA");
``` [3](#0-2)  This is a structural limitation, not a bug the AA author can work around: AAs cannot produce `spend_proofs`, which are mandatory for any private-asset payment message, per `validateMessage`'s check that `spend_proofs` are forbidden in AA units in the first place [4](#0-3) .

3. Nothing in the pre-send validation path stops a normal wallet user (an "unprivileged unit poster") from sending a private-asset payment to an AA address. `checkAAOutputs()` — the only AA-specific pre-flight check performed by `wallet.js:sendMultiPayment` before composing a payment to an AA — validates only that bounce fees are covered; it does not inspect asset privacy or reject private payments to AA addresses at all [5](#0-4) . The unit itself will validate fine at the protocol level, because private payment validation (`validatePayment`/`validatePaymentInputsAndOutputs` in `validation.js`) has no special-casing for AA-address recipients [6](#0-5) .

The result: the private payment is accepted and stable, the output sits at the AA's address forever, but it is invisible to the AA's own accounting (`aa_balances`) and can never be moved by the AA (bounced with "sending private asset from AA") or by anyone else (the AA address has no private key/owner who could construct a private payment chain on its behalf).

### Impact Explanation
This matches the "AA fund loss or freezing" impact category explicitly allowed by the validation rules. Just like the ETH-unwrapping report describes native ETH stuck at a contract that cannot unwrap it, here private-asset value sent to an AA becomes permanently unspendable and unaccounted-for. There is no recovery path in the current codebase: the AA cannot see the balance to include it in any bounce/refund logic, and it categorically cannot construct a valid private-asset payment message even if it tried. Depending on the value and denomination of the private asset (divisible or fixed-denomination, e.g., blackbytes), an attacker or an unaware user routing a private payment into an AA-controlled DeFi contract, DEX, or vault would cause an unrecoverable loss of funds for the sender, with no bounce/refund possible because bounce logic can also never touch that private balance.

### Likelihood Explanation
Likelihood is Medium: this requires only a normal, unprivileged user (or an attacker griefing another user) constructing a standard private-asset payment (fully within existing wallet/composer APIs) with an AA address as the recipient. No special permission, race condition, or malicious hub/peer is needed — this is reachable purely through normal payment composition and unit posting, matching the "unprivileged unit poster ... paired device / private-payment counterparty" reachable-actor requirement. The main mitigating factor is that ordinary GUI wallets may not proactively warn users when sending a private asset to an AA address (as `checkAAOutputs` does not flag it), so the trigger is realistically accidental misuse or a social-engineering/griefing attack rather than a common occurrence, but no protocol-level barrier prevents it.

### Recommendation
Add an explicit guard, analogous to the missing "unwrap" functionality being added in the reference report, so that private-asset payments destined for AA addresses are rejected before they are ever accepted/stabilized:
- In `checkAAOutputs()` (`aa_addresses.js`), look up asset privacy via `storage.loadAsset`/`readAsset` for every non-base asset in `arrPayments` and reject (client-side) any payment to an AA address where the asset `is_private`.
- More importantly, add a protocol-level (`validation.js`) rule in `validatePayment`/`validatePaymentInputsAndOutputs`, or in `validateMessage`, that rejects any private-asset payment output whose address belongs to `aa_addresses` (mirroring the existing `checkNotAAs` pattern already used for other privileged operations) so that non-compliant clients cannot bypass the wallet-side check and cause value to become permanently stuck.

### Proof of Concept
1. Deploy any Autonomous Agent `A` with arbitrary logic (no special configuration required).
2. Define (or use an existing) private, divisible or fixed-denomination asset `P` with `is_private: true`.
3. From a normal wallet, use `sendMultiPayment` / `composeDivisibleAssetPaymentJoint` (or the indivisible-asset equivalent) to send an amount of `P` to AA address `A`, exactly as one would send it to any regular address. `checkAAOutputs()` only checks bounce fees and permits the transaction [5](#0-4) .
4. The unit validates and stabilizes normally (private payment validation has no AA-specific restriction — see `validation.js` `validatePayment`).
5. Observe that `aa_balances` for address `A` never reflects asset `P` (filtered out by `is_private=0 OR is_private IS NULL` in `storage.js` line 960 and `aa_composer.js` line 1978), so no AA trigger logic conditioned on `balance[P]` or `trigger.output[[asset=P]]` can ever fire for this payment.
6. Any attempt by AA `A` to construct a payment message spending asset `P` back to the sender is unconditionally rejected inside `sendUnit()` with `"sending private asset from AA"` [3](#0-2) , and no external party holds the keys needed to build a compliant private-payment chain from the AA's address. The sent value is permanently frozen.

**Note on uncertainty:** I could not find any code path (in the searched files) that treats private outputs to an AA any differently once stabilized — e.g., an automatic "refund on receipt of unsupported asset" mechanism. If such logic exists elsewhere in the repository outside what the index returned, it would mitigate this finding; I was unable to confirm its absence beyond the files reviewed (`aa_composer.js`, `aa_addresses.js`, `storage.js`, `validation.js`, `private_payment.js`, `network.js`).

### Citations

**File:** storage.js (L954-961)
```javascript
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
```

**File:** aa_composer.js (L1329-1330)
```javascript
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1969-1979)
```javascript
				var sql_fill_temp = "INSERT INTO aa_outputs_balances (address, asset, calculated_balance) \n\
					SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) \n\
					FROM aa_addresses \n\
					CROSS JOIN outputs USING(address) \n\
					CROSS JOIN units ON outputs.unit=units.unit \n\
					LEFT JOIN assets ON outputs.asset=assets.unit \n\
					WHERE is_spent=0 AND sequence='good' AND ( \n\
						is_stable=1 \n\
						OR is_stable=0 AND is_aa_response=1 \n\
					) AND (is_private=0 OR is_private IS NULL) \n\
					GROUP BY address, asset";
```

**File:** validation.js (L1539-1541)
```javascript
	if ("spend_proofs" in objMessage){
		if (objValidationState.bAA)
			return callback("spend proofs in AA");
```

**File:** validation.js (L2060-2124)
```javascript
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

**File:** aa_addresses.js (L120-156)
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
}
```
