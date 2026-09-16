### Title
`is_valid_signed_package()` / `getSignedPackageHashToSign()` omit any binding to the requesting AA's address, enabling cross-contract signature replay — (File: `object_hash.js`)

### Summary
The oscript primitive `is_valid_signed_package(signed_package, address)`, implemented via `signed_message.validateSignedMessage()` and `objectHash.getSignedPackageHashToSign()`, verifies only that a given address signed the bytes of `signed_message` (plus `authors`/`last_ball_unit`/`version`). Nothing in the hashed structure binds the signature to the specific AA (`this_address`) that is consuming it. This is the same class of bug as the Opera-Bridge finding: the signed hash carries no "domain" (destination contract) identifier, so a signature that is valid for one AA instance can be replayed against any other AA instance/definition that accepts signed packages with the same off-chain message shape.

### Finding Description
`getSignedPackageHashToSign()` builds the hash to be signed purely from the caller-supplied object: [1](#0-0) 
It strips only `authentifiers`; it never includes `this_address`, the AA definition hash, or any other value identifying which contract the signature is meant for.

`validateSignedMessage()` (used by the `is_valid_signed_package` formula op) verifies exactly this hash and only checks that the recovered signer matches the `address` argument passed by the calling AA — it performs no check that the signed content is scoped to the calling AA: [2](#0-1) [3](#0-2) 

Because the hashing/signing primitive provides no built-in domain separation, it is entirely up to each AA author to manually embed a self-referencing field (e.g. `this_address`) inside `signed_message` and check it. The bundled `payment_channels.oscript` sample does this defensively: [4](#0-3) 
proving the protocol itself does not enforce or guarantee this binding — it is a convention the AA author must remember to add.

The bundled `order_book_exchange.oscript` sample, by contrast, does **not** bind the signed order to the specific exchange AA instance: the order's dedup id and the `is_valid_signed_package` call use only `sell_asset`, `buy_asset`, `sell_amount`, `price` and `last_ball_unit`, never `this_address`: [5](#0-4) 
A signed order created by a user intending to trade through one order-book AA instance therefore hashes/signs identically regardless of which AA consumes it, and remains valid indefinitely (deduplication is only local to the consuming AA's own `var['executed_'||$id]` state).

### Impact Explanation
If the same oscript template (or any AA design that reuses `is_valid_signed_package` without independently embedding `this_address`/contract identity in the signed content) is deployed more than once — e.g. a redeployed/upgraded exchange AA, a competing/cloned AA using the identical order format, or a maliciously deployed look-alike AA — a legitimately signed order/message obtained by any observer (orders posted in a public book are visible on-chain/off-chain) can be resubmitted and accepted as valid by a different AA instance that the user never intended to trade with. Because AA authors reach for this same "sign off-chain, verify on-chain" primitive for financial logic (payment channels, order books, escrows), a missing domain separator is a fund-loss/authorization bypass in AA logic: an attacker can direct a user's balance in AA #2 to be spent according to terms the user only authorized for AA #1, or replay a stale/cross-context order to execute an unintended trade. This falls into "AA fund loss" and "unauthorized spending" territory. Severity is Medium: exploitability depends on the specific AA design reusing signed packages across instances/definitions without adding its own binding field (as `order_book_exchange.oscript` demonstrates the base template does not).

### Likelihood Explanation
Likelihood is Medium: exploitation requires an AA author to build an `is_valid_signed_package`-based contract without independently adding a self-referencing/contract-identity field to the signed content — exactly the gap the shipped `order_book_exchange.oscript` example exhibits. Any user, AA author, or attacker can construct or observe a signed package (no special privilege needed) and resubmit it via a normal trigger to any AA instance that accepts the same message schema, since the protocol's own hashing primitive performs no domain separation.

### Recommendation
Harden the primitive at the protocol level rather than relying solely on AA-author discipline:
- Extend `getSignedPackageHashToSign()` (and/or the `is_valid_signed_package` formula op in `formula/evaluation.js`) to optionally/mandatorily incorporate the verifying AA's `this_address` (and/or `asset`/definition context) into the hash, similar to EIP-712 domain separation, so a signature verified successfully by one AA cannot be replayed against another.
- At minimum, update documentation/oscript linting (`formula/validation.js`) to warn or require that any `signed_message` object passed to `is_valid_signed_package` include a self-referencing `this_address` (or equivalent contract-identity) field that is checked by the consuming AA, matching the pattern already used in `payment_channels.oscript`.
- Update bundled sample templates (e.g. `order_book_exchange.oscript`) to include and check `this_address` in the signed order content, since these samples are used as reference implementations.

### Proof of Concept
1. User Alice signs an order via `signMessage`/`is_valid_signed_package`-compatible content: `{sell_asset, buy_asset, sell_amount, price}` intended for order-book AA instance `OB1`, per `test/samples/order_book_exchange.oscript` lines 29-49.
2. The signed package hash is computed by `objectHash.getSignedPackageHashToSign()` — note it never includes `OB1`'s address.
3. A second AA instance `OB2`, deployed from the same or a compatible oscript template (e.g. an upgraded or forked version of the exchange), also calls `is_valid_signed_package(trigger.data.order1, $order1.address)` with the exact same signature-check logic.
4. Anyone (attacker, or Alice herself unintentionally) resubmits Alice's previously observed signed order as `trigger.data.order1` to `OB2`. Because `validateSignedMessage()`/`getSignedPackageHashToSign()` only check that `$order1.address` signed the message bytes — with no reference to `OB2`'s address anywhere in the hash — `is_valid_signed_package` returns `true`, and `OB2` executes the trade against Alice's balance in `OB2`, even though Alice never authorized trading through `OB2`.

### Citations

**File:** object_hash.js (L97-103)
```javascript
function getSignedPackageHashToSign(signedPackage) {
	var unsignedPackage = _.cloneDeep(signedPackage);
	for (var i=0; i<unsignedPackage.authors.length; i++)
		delete unsignedPackage.authors[i].authentifiers;
	var sourceString = (typeof signedPackage.version === 'undefined' || signedPackage.version === constants.versionWithoutTimestamp) ? getSourceString(unsignedPackage) : getJsonSourceString(unsignedPackage);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest();
}
```

**File:** signed_message.js (L260-272)
```javascript
			validateOrReadDefinition(objAuthor, function (arrAddressDefinition, _last_ball_mci, last_ball_timestamp) {
				last_ball_mci = _last_ball_mci;
				var objUnit = _.clone(objSignedMessage);
				objUnit.messages = []; // some ops need it
				try {
					var objValidationState = {
						unit_hash_to_sign: objectHash.getSignedPackageHashToSign(objSignedMessage),
						last_ball_mci: last_ball_mci,
						last_ball_timestamp: last_ball_timestamp,
						bNoReferences: !bNetworkAware,
						complexity,
						max_complexity,
					};
```

**File:** formula/evaluation.js (L1653-1699)
```javascript
			case 'is_valid_signed_package':
				if (!objValidationState.count_signed_packages)
					objValidationState.count_signed_packages = 0;
				if (objValidationState.count_signed_packages >= constants.MAX_SIGNED_PACKAGES_PER_AA_EVAL && bPostPemCurvesFix)
					return setFatalError("too many signed packages in evaluation", { arr }, false, cb);
				objValidationState.count_signed_packages++;
				var signed_package_expr = arr[1];
				var address_expr = arr[2];
				evaluate(address_expr, function (evaluated_address) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isValidAddress(evaluated_address))
						return setFatalError("bad address in is_valid_signed_package: " + evaluated_address, { arr }, false, cb);
					evaluate(signed_package_expr, async function (signedPackage) {
						if (fatal_error)
							return cb(false);
						if (!(signedPackage instanceof wrappedObject))
							return cb(false);
						signedPackage = signedPackage.obj;
						if (ValidationUtils.hasFieldsExcept(signedPackage, ['signed_message', 'last_ball_unit', 'authors', 'version']))
							return cb(false);
						if (signedPackage.version) {
							if (typeof signedPackage.version !== 'string')
								return cb(false);
							if (signedPackage.version === constants.versionWithoutTimestamp)
								return cb(false);
							const fVersion = parseFloat(signedPackage.version);
							const maxVersion = 4; // depends on mci in the future updates
							if (fVersion > maxVersion)
								return cb(false);
						}
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
						}
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
```

**File:** test/samples/payment_channels.oscript (L40-46)
```text
							if (trigger.data.sentByPeer){
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
```

**File:** test/samples/order_book_exchange.oscript (L38-49)
```text
					$sell_key1 = 'balance_' || $order1.address || '_' || $order1.sell_asset;
					$sell_key2 = 'balance_' || $order2.address || '_' || $order2.sell_asset;

					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;
```
