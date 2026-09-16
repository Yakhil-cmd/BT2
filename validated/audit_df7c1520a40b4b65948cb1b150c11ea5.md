### Title
Missing Upper Bound on `tps_fee`/`burn_fee` Lets a Malicious Co-signer Drain a Shared Address via a Signing Request - (File: `wallet.js`, `validation.js`, `composer.js`)

### Summary
The external report describes a Starknet account where escape transactions signed by a single, limited-privilege Guardian have no upper bound on the fee fields (`L1_GAS`/`L2_GAS` `max_price_per_unit` × `max_amount`), so a non-honest fee collector (sequencer) colluding with the Guardian could drain the account through "legitimate" fee extraction rather than an outright unauthorized transfer. The analogous mechanism in ocore is the `tps_fee`/`burn_fee` fields of a payment unit, which are freely chosen by whoever *composes* the unit but are consumed straight out of the paying address's balance. When the composing party and the address's key-holder(s) are different devices — the normal "shared/multisig address" and "paired device" cosigning flow — the fee amount is never bounded for the party being asked to co-sign.

### Finding Description
`tps_fee`, `oversize_fee` and `burn_fee` are deducted from the payment unit's inputs together with `headers_commission`/`payload_commission`: [1](#0-0) 

At consensus level, `validateTpsFee` only enforces a **lower bound** (the fee must be at least the current network-required minimum); there is no upper bound check anywhere in `validation.js`: [2](#0-1) 

The only place an upper-bound sanity check exists is client-side, inside `composer.composeJoint`, which compares `oversize_fee + tps_fee` to a `max_fee_ratio` multiple of the base size fees: [3](#0-2) 

This check runs only when *the local node* is the one calling `composeJoint` to build the unit. It is bypassed entirely on the receiving side of a cosigning flow: when another device sends a `"sign"` request over the hub with an already fully-formed `unsigned_unit` (containing `headers_commission`, `payload_commission`, `oversize_fee`, `tps_fee`, `burn_fee` already set), `wallet.js`'s handler validates structural fields (address, signing path, payload hashes, output/ input shapes) but never re-derives or bounds the fee fields against the unit's size: [4](#0-3) 

The unit is then handed to `network.handleOnlineJoint` for normal network validation, and only after it validates (which it will, since only a floor is enforced) does the wallet fire a `"signing_request"` event to prompt the user/UI: [5](#0-4) 

Thus, for a shared (multisig) address whose signing key is split across cosigner devices — including the "paired device" pattern used throughout `wallet_defined_by_addresses.js` and `arbiter_contract.js` — a malicious cosigner can craft a unit that pays a legitimate-looking small amount to a counterparty but sets `tps_fee`/`burn_fee` to an arbitrarily large value (limited only by the address's spendable balance and `MAX_CAP`), then request the other cosigner(s) to sign it. Nothing in the validation or signing-request pipeline rejects or even flags the excessive fee; it depends entirely on the receiving human noticing the fee in the UI, which is not guaranteed since wallets typically foreground the amount/recipient, not the size-based commission breakdown.

### Impact Explanation
If exploited, a co-signer of a shared/multisig address can extract funds from the address disguised as a "network fee" rather than an output to an attacker address, bypassing the normal expectation that all cosigners must approve the actual value being moved. Since `tps_fee` accrues to headers-commission recipients / OP addresses and `burn_fee` is destroyed, the honest cosigner(s) get no recourse once the unit is signed and stabilizes — this is a genuine unauthorized-spending / fund-loss scenario for a shared address, mirroring the "malicious Guardian drains funds via unconstrained fee" pattern in the original report.

### Likelihood Explanation
Requires the attacker to already be a legitimate cosigner (or a "paired device") of the shared/multisig address — this satisfies the report's threat model of a partially-privileged, non-fully-trusted party (analogous to the Guardian) rather than a fully external attacker. It also relies on the other cosigner(s)' UI/review process not surfacing the fee amount clearly, which is plausible given that most wallet UIs emphasize the destination address and payment amount over the commission/tps_fee/burn_fee breakdown. No malicious node/sequencer collusion is even needed in ocore (unlike the Starknet report, which required a non-nice sequencer) because the fee amount here is directly consumed from the address's balance at face value with no discretionary "actual cost" step — making this arguably easier to exploit than the original Starknet issue.

### Recommendation
Apply the same `max_fee_ratio`-style bound enforced in `composer.composeJoint` (`composer.js:522-529`) as a mandatory, non-bypassable check whenever a device is asked to co-sign a unit it did not compose itself — i.e., add a fee-ratio/absolute-cap check inside the `"sign"` handler of `wallet.js` (around lines 251-330) before firing the `"signing_request"` event, and/or move this bound into `validation.js`'s `validateTpsFee`/burn-fee validation so it is enforced consistently for every unit regardless of who composed it, not just when the local `composer.js` is used.

### Proof of Concept
1. Attacker device is a legitimate cosigner of shared address `S` (2-of-2 or n-of-m multisig).
2. Attacker crafts `unsigned_unit` with a payment message: small `output` to attacker's own other address, but sets `objUnit.tps_fee` (or `burn_fee`) far above the network-required minimum, consuming most of `S`'s spendable balance as "fee".
3. Attacker computes `headers_commission`/`payload_commission` correctly (required to pass `objectLength` checks) and sends a `"sign"` device message (`subject: "sign"`) to the honest cosigner, per the flow in `wallet.js:251-330`.
4. Honest device validates payload hashes, output/input shapes, and structural fields — all pass, since none of these checks bound `tps_fee`/`burn_fee`. `network.handleOnlineJoint` validates the unit against consensus rules (`validation.js`), which only checks the tps_fee floor, not a ceiling.
5. `"signing_request"` fires; if the UI does not clearly highlight the abnormal fee, the honest cosigner signs, and the unit is broadcast/stabilizes, draining `S`'s balance through the inflated fee field.

**Uncertainty note:** I could not fully verify within the available searches whether any additional UI-level warning specific to abnormal `tps_fee`/`burn_fee` exists in a GUI wallet layer outside the indexed `ocore` core files (headless/core library only) — such UI code may live in a separate GUI repository not covered by this index. This finding is based on the core validation/composition/signing logic in `ocore` itself.

### Citations

**File:** validation.js (L1050-1097)
```javascript
async function validateTpsFee(conn, objJoint, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || !objValidationState.last_ball_mci)
		return callback();
	const objUnit = objJoint.unit;
	if (objValidationState.bAA) {
		if ("tps_fee" in objUnit)
			return callback("tps_fee in AA response");
		return callback();
	}
	if ("content_hash" in objUnit) // tps_fee and other unit fields have been already stripped
		return callback();
	const objUnitProps = {
		unit: objUnit.unit,
		parent_units: objUnit.parent_units,
		best_parent_unit: objValidationState.best_parent_unit,
		last_ball_unit: objUnit.last_ball_unit,
		timestamp: objUnit.timestamp,
		count_primary_aa_triggers: objValidationState.count_primary_aa_triggers,
		max_aa_responses: objUnit.max_aa_responses,
	};
	const count_units = storage.getCountUnitsPayingTpsFee(objUnitProps);
	const min_tps_fee = await storage.getLocalTpsFee(conn, objUnitProps, count_units);
	console.log('validation', {min_tps_fee}, objUnitProps)
	
	// compare against the current tps fee or soft-reject
	const current_tps_fee = objJoint.ball ? 0 : storage.getCurrentTpsFee(0, count_units); // very low while catching up
	const min_acceptable_tps_fee_multiplier = objJoint.ball ? 0 : storage.getMinAcceptableTpsFeeMultiplier();
	const min_acceptable_tps_fee = current_tps_fee * min_acceptable_tps_fee_multiplier * count_units;

	const author_addresses = objUnit.authors.map(a => a.address);
	const bFromOP = isFromOP(author_addresses, objValidationState.last_ball_mci);
	const recipients = storage.getTpsFeeRecipients(objValidationState.last_ball_mci < constants.tpsFeeRecipientsFixMci ? objUnit.earned_headers_commission_recipients : storage.ehcr2assoc(objUnit.earned_headers_commission_recipients), author_addresses);
	for (let address in recipients) {
		const share = recipients[address] / 100;
		if (!share)
			throw Error(`invalid share for address ${address}: ${share}`);
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
		const tps_fee = tps_fees_balance / share + objUnit.tps_fee;
		if (tps_fee < min_acceptable_tps_fee) {
			if (!bFromOP)
				return callback(createTransientError(`tps fee on address ${address} must be at least ${min_acceptable_tps_fee}, found ${tps_fee}`));
			console.log(`unit from OP, hence accepting despite low tps fee on address ${address} which must be at least ${min_acceptable_tps_fee} but found ${tps_fee}`);
		}
	}
	callback();
```

**File:** validation.js (L2661-2667)
```javascript
			else{ // base asset
				const vote_count_fee = objUnit.messages.find(m => m.app === 'system_vote_count') ? constants.SYSTEM_VOTE_COUNT_FEE : 0;
				const oversize_fee = objUnit.oversize_fee || 0;
				const tps_fee = objUnit.tps_fee || 0;
				const burn_fee = objUnit.burn_fee || 0;
				if (total_input !== total_output + objUnit.headers_commission + objUnit.payload_commission + oversize_fee + tps_fee + burn_fee + vote_count_fee)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output+" + "+objUnit.headers_commission+" + "+objUnit.payload_commission+" + "+oversize_fee+" + "+tps_fee+" + "+burn_fee+" + "+vote_count_fee);
```

**File:** composer.js (L522-529)
```javascript
	], function(err){
		if (!err && last_ball_mci >= constants.v4UpgradeMci) {
			const size_fees = objUnit.headers_commission + objUnit.payload_commission;
			const additional_fees = (objUnit.oversize_fee || 0) + objUnit.tps_fee;
			const max_ratio = params.max_fee_ratio || conf.max_fee_ratio || 100;
			if (additional_fees > max_ratio * size_fees)
				err = `additional fees ${additional_fees} (oversize fee ${objUnit.oversize_fee || 0} + tps fee ${objUnit.tps_fee}) would be more than ${max_ratio} times the regular fees ${size_fees}`;
		}
```

**File:** wallet.js (L251-330)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object" || objUnit === null)
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				try {
					objUnit.authors.forEach(function (author) {
						var authentifiers = author.authentifiers;
						for (var path in authentifiers)
							authentifiers[path] = authentifiers[path].replace(/./g, '-');
					});
					const authorAddresses = objUnit.authors.map(author => author.address);
					if (!authorAddresses.includes(body.address))
						return callbacks.ifError("address not found among authors");
				}
				catch (e) {
					return callbacks.ifError("invalid authors: " + e.toString());
				}
				var assocPrivatePayloads = body.private_payloads;
				if ("private_payloads" in body){
					if (!isNonemptyObject(assocPrivatePayloads))
						return callbacks.ifError("bad private payloads");
					if (!ValidationUtils.isNonemptyArray(objUnit.messages))
						return callbacks.ifError("private payloads require messages");
					const sent_pp_hashes = Object.keys(assocPrivatePayloads).sort();
					const expected_pp_hashes = objUnit.messages.filter(m => m.payload_location === "none" && m.app === "payment").map(m => m.payload_hash).sort();
					if (!_.isEqual(sent_pp_hashes, expected_pp_hashes))
						return callbacks.ifError("private payloads are not the same as in the messages");
					for (var payload_hash in assocPrivatePayloads){
						try {
							const payload = assocPrivatePayloads[payload_hash];
							if (!ValidationUtils.isNonemptyArray(payload.outputs) || !payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isNonemptyString(o.blinding) && ValidationUtils.isPositiveInteger(o.amount)))
								return callbacks.ifError("bad private payload outputs");
							if (!ValidationUtils.isNonemptyArray(payload.inputs) || !payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
								return callbacks.ifError("bad private payload inputs");
							const hidden_payload = _.cloneDeep(payload);
							if (payload.denomination) { // indivisible asset.  In this case, payload hash is calculated based on output_hash rather than address and blinding
								if (!payload.outputs.every(o => o.output_hash === objectHash.getBase64Hash({ address: o.address, blinding: o.blinding })))
									return callbacks.ifError("output hash mismatch");
								hidden_payload.outputs.forEach(function (o) {
									delete o.address;
									delete o.blinding;
								});
							}
							var calculated_payload_hash = objectHash.getBase64Hash(hidden_payload, bJsonBased);
						}
						catch (e) {
							return callbacks.ifError("hidden payload hash failed: " + e.toString());
						}
						if (payload_hash !== calculated_payload_hash)
							return callbacks.ifError("private payload hash does not match");
						if (objUnit.messages.filter(function(objMessage){ return (objMessage && objMessage.payload_hash === payload_hash); }).length !== 1)
							return callbacks.ifError("no such payload hash in the messages");
					}
				}
				if (("messages" in objUnit) + ("signed_message" in objUnit) !== 1)
					return callbacks.ifError("either messages or signed_message must be present, but not both");
				if ("messages" in objUnit){
					const validation = require('./validation.js');
					if (!validation.hasValidPayloadHashes({ unit: objUnit }))
						return callbacks.ifError("invalid payload hashes");
					if (!objUnit.messages.find(m => m.app === 'payment'))
						return callbacks.ifError("no payment messages");
					for (let m of objUnit.messages) {
						if (m.app !== 'payment' || m.payload_location !== 'inline') continue;
						if (!ValidationUtils.isNonemptyArray(m.payload.outputs) || !m.payload.outputs.every(o => ValidationUtils.isValidAddress(o.address) && ValidationUtils.isPositiveInteger(o.amount)))
							return callbacks.ifError("invalid payment outputs");
						if (!ValidationUtils.isNonemptyArray(m.payload.inputs) || !m.payload.inputs.every(i => ("type" in i) || (ValidationUtils.isNonemptyString(i.unit) && ValidationUtils.isNonnegativeInteger(i.message_index) && ValidationUtils.isNonnegativeInteger(i.output_index))))
							return callbacks.ifError("invalid payment inputs");
					}
				}
```

**File:** wallet.js (L357-372)
```javascript
							var objJoint = {unit: objUnit, unsigned: true};
							eventBus.once("validated-"+objUnit.unit, function(bValid){
								if (!bValid){
									console.log("===== unit in signing request is invalid");
									return;
								}
								// This event should trigger a confirmation dialog.
								// If we merge coins from several addresses of the same wallet, we'll fire this event multiple times for the same unit.
								// The event handler must lock the unit before displaying a confirmation dialog, then remember user's choice and apply it to all
								// subsequent requests related to the same unit
								eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							});
							// if validation is already under way, handleOnlineJoint will quickly exit because of assocUnitsInWork.
							// as soon as the previously started validation finishes, it will trigger our event handler (as well as its own)
							network.handleOnlineJoint(ws, objJoint);
						//});
```
