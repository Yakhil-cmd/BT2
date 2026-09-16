### Title
Off-chain signed AA messages (`is_valid_signed_package`) have no revocation/expiry mechanism, allowing execution of orders/commands the signer no longer wants honored - ([File: formula/evaluation.js], [File: signed_message.js])

### Summary
Obyte's oscript language lets an AA accept an off-chain `signed_package` (a `signed_message` + `authors` + optional `last_ball_unit`) as an authenticated instruction, verified through the `is_valid_signed_package` opcode which delegates to `signed_message.validateSignedMessage`. This mechanism is the DAG analog of the report's off-chain signed command: a user signs a message once (e.g. a trade order or a payment-channel state update) and hands it to a counterparty or keeps it for later submission. There is no nonce, sequence number, or on-chain revocation list associated with these packages, so once a message is signed there is no way for its author to invalidate it before someone submits it to the AA — the only "cancellation" available (draining the referenced balance) is itself vulnerable to races and is explicitly left unimplemented in the reference implementation.

### Finding Description
`is_valid_signed_package` verifies a signed package purely by checking the ECDSA signature against the address definition and, if present, that `last_ball_unit` is stable and on the main chain. [1](#0-0) 

The underlying verification in `signed_message.validateSignedMessage` only checks structural validity, address/definition consistency and the authentifier(s); it does not check any nonce, counter, or revocation flag tied to the message content. [2](#0-1) [3](#0-2) 

The reference `order_book_exchange.oscript` AA — shipped as the canonical example of this pattern — demonstrates the consequence directly. It computes an order id as a deterministic hash of the order fields (`$id1 = sha256($order1.address || ... || trigger.data.order1.last_ball_unit)`), tracks only `executed_<id>` / `amount_left_<id>` state vars, and explicitly notes cancellation/expiry is unimplemented ("// to do check expiry"). [4](#0-3) 

Because the only thing that stops a stale order from executing is the trader's on-chain balance (`var[$sell_key1]`), a signer who wishes to cancel an order they already shared off-chain has no on-chain primitive to do so: withdrawing funds is subject to race conditions (a counterparty unit and a withdrawal unit can both build on the same last stable state and both pass validation, since AA balance checks are evaluated at execution time against whatever state exists then), and there is no `nonce`/`invalidate` opcode analogous to what the report recommends for `ExecutionModule`. The same pattern recurs in `payment_channels.oscript`, where a peer's stale signed state (`sentByPeer`) remains valid and enforceable via `is_valid_signed_package` indefinitely, with cancellation only implicit in the channel's own `period` bookkeeping. [5](#0-4) 

### Impact Explanation
Any AA that accepts `is_valid_signed_package`-based commands (orders, channel updates, meta-transactions relayed by a third party) inherits this gap: a user who signs and shares an off-chain instruction cannot reliably revoke it. If the referenced balance/state is not drained before the instruction is submitted, it will execute even though the signer no longer intends it — leading to unwanted trades, fund transfers, or state changes executed against the signer's current wishes (fund loss/freezing analog to the original report). Because withdrawal-vs-execution ordering is race-prone at the AA level, an attacker (the counterparty, or anyone holding the signed package) can front-run a cancellation attempt.

### Likelihood Explanation
Any AA author using `is_valid_signed_package` for off-chain-authorized actions (a documented, encouraged oscript pattern) is exposed unless they build their own nonce/registry logic, which the reference examples in this same codebase do not do. Exploitation requires only that the signer wants to cancel after sharing a signed package and that the counterparty/attacker submits it before the signer's mitigating on-chain action (e.g., balance withdrawal) becomes final — a realistic race given typical DAG confirmation delays.

### Recommendation
Add a first-class oscript primitive (or a documented, safe pattern) for revoking/expiring `signed_package`s, e.g.:
- Support an optional `nonce`/`expiry` field inside `signed_message` payloads that AAs can check against a per-address on-chain counter, and
- Provide a built-in opcode (analogous to `seen definition change`) such as `seen nonce` or `is_valid_signed_package` variant that lets an AA verify a package's nonce is still the current one, so the signer can invalidate stale packages by issuing a single on-chain "bump nonce" transaction rather than relying on balance races.
Update reference AAs (`order_book_exchange.oscript`, `payment_channels.oscript`) to implement the previously TODO'd expiry check.

### Proof of Concept
1. Alice signs an order (or payment-channel state update) off-chain and sends it to Bob per the `order_book_exchange.oscript` pattern shown above.
2. Alice later decides to cancel and issues a withdrawal transaction for the balance backing the order.
3. Bob, holding the still-valid signed package, submits a matching trigger in the same time window; because `is_valid_signed_package` only checks the signature/definition (not any cancellation state), and AA execution order between Alice's withdrawal and Bob's trigger is not guaranteed, Bob's unit can be processed first and the trade executes against Alice's balance despite her attempted cancellation, per the validation path in [1](#0-0)  and the order-matching logic in [6](#0-5) .

### Citations

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

**File:** signed_message.js (L117-181)
```javascript
function validateSignedMessage(conn, objSignedMessage, address, mci, handleResult) {
	if (!handleResult) {
		if (mci) { // validateSignedMessage(conn, objSignedMessage, address, handleResult)
			handleResult = mci;
			mci = undefined;
		}
		else { // validateSignedMessage(objSignedMessage, handleResult)
			handleResult = objSignedMessage;
			objSignedMessage = conn;
			conn = db;
		}
	}
	const max_complexity = (mci >= constants.pemCurvesFixMci) ? 10 : 0;
	if (!ValidationUtils.isNonemptyObject(objSignedMessage))
		return handleResult("signed message must be a non-empty object");
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
	var authors = objSignedMessage.authors;
	if (!ValidationUtils.isNonemptyArray(authors))
		return handleResult("no authors");
	if (!address && !ValidationUtils.isArrayOfLength(authors, 1))
		return handleResult("authors not an array of len 1");
	if (authors.length > constants.MAX_AUTHORS_PER_UNIT)
		return handleResult("too many authors");
	var prev_address = "";
	var the_author;
	for (var i = 0; i < authors.length; i++){
		var author = authors[i];
		if (!ValidationUtils.isNonemptyObject(author))
			return handleResult("author must be a non-empty object");
		if (!ValidationUtils.isValidAddress(author.address))
			return handleResult("not valid address");
		if (author.address <= prev_address)
			return handleResult("author addresses not sorted");
		prev_address = author.address;
		if (ValidationUtils.hasFieldsExcept(author, ['address', 'definition', 'authentifiers']))
			return handleResult("foreign fields in author");
		if ("definition" in author) {
			if (!ValidationUtils.isArrayOfLength(author.definition, 2))
				return handleResult("definition must be an array of length 2");
			if (author.definition[0] === 'autonomous agent')
				return handleResult('AA cannot be defined in authors');
			try {
				if (objectHash.getChash160(author.definition) !== author.address)
					return handleResult("wrong definition: " + objectHash.getChash160(author.definition) + "!==" + author.address);
			}
			catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
		}
		if (author.address === address)
			the_author = author;
		if (!ValidationUtils.isNonemptyObject(author.authentifiers))
			return handleResult("no authentifiers");
		for (let path in author.authentifiers) {
			if (!ValidationUtils.isNonemptyString(author.authentifiers[path]))
				return handleResult("authentifiers must be nonempty strings");
			if (author.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return handleResult("authentifier too long");
		}
	}
```

**File:** signed_message.js (L255-303)
```javascript
	let last_ball_mci;
	let complexity = 0;
	async.eachSeries(
		authors,
		function (objAuthor, cb) {
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
				}
				catch (e) {
					return cb("failed to calc unit_hash_to_sign: " + e);
				}
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
				}
				catch (e) {
					console.log("exception while validating signed message:", e);
					return cb("exception while validating: " + e);
				}
			});
		},
		function (err) {
			if (err)
				return handleResult(err);
			handleResult(null, last_ball_mci);
		}
	);
}
```

**File:** test/samples/order_book_exchange.oscript (L27-98)
```text
			{ // execute orders, order1 must be smaller or the same as order2; order2 is partially filled
				if: `{
					$order1 = trigger.data.order1.signed_message;
					$order2 = trigger.data.order2.signed_message;
					if (!$order1.sell_asset OR !$order2.sell_asset)
						return false;
					if ($order1.sell_asset != $order2.buy_asset OR $order1.buy_asset != $order2.sell_asset)
						return false;

					// to do check expiry

					$sell_key1 = 'balance_' || $order1.address || '_' || $order1.sell_asset;
					$sell_key2 = 'balance_' || $order2.address || '_' || $order2.sell_asset;

					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;

					$amount_left1 = var['amount_left_' || $id1] otherwise $order1.sell_amount;
					$amount_left2 = var['amount_left_' || $id2] otherwise $order2.sell_amount;

					if ($amount_left1 > var[$sell_key1] OR $amount_left2 > var[$sell_key2])
						return false;

					$buy_amount1 = round($amount_left1 * $order1.price);
					if ($buy_amount1 > $amount_left2) // order1 is not the smaller one
						return false;
					$expected_buy_amount2 = round($buy_amount1 * $order2.price);
					if ($expected_buy_amount2 > $amount_left1) // user2 doesn't like the price, he gets less than expects
						return false;

					true
				}`,
				messages: [{
					app: 'state',
					state: `{
						$buy_key1 = 'balance_' || $order1.address || '_' || $order1.buy_asset;
						$buy_key2 = 'balance_' || $order2.address || '_' || $order2.buy_asset;
						$base_key1 = 'balance_' || $order1.address || '_base';
						$base_key2 = 'balance_' || $order2.address || '_base';

						var[$sell_key1] = var[$sell_key1] - $amount_left1;
						var[$sell_key2] = var[$sell_key2] - $buy_amount1;
						var[$buy_key1] = var[$buy_key1] + $buy_amount1;
						var[$buy_key2] = var[$buy_key2] + $amount_left1;

						$fee = 1000;
						var[$base_key1] = var[$base_key1] - $fee;
						var[$base_key2] = var[$base_key2] - $fee;
						if (var[$base_key1] < 0 OR var[$base_key2] < 0)
							bounce('not enough balance for fees');

						var['executed_' || $id1] = 1;
						$new_amount_left2 = $amount_left2 - $buy_amount1;
						if ($new_amount_left2)
							var['amount_left_' || $id2] = $new_amount_left2;
						else
							var['executed_' || $id2] = 1;

						// parsable response for transaction log
						response[$order1.address || '_' || $order1.sell_asset] = -$amount_left1;
						response[$order2.address || '_' || $order2.buy_asset] = $amount_left1;
						response[$order1.address || '_' || $order1.buy_asset] = $buy_amount1;
						response[$order2.address || '_' || $order2.sell_asset] = -$buy_amount1;
					}`
				}]
```

**File:** test/samples/payment_channels.oscript (L40-49)
```text
							if (trigger.data.sentByPeer){
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
								$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
								if ($transferredFromPeer < 0)
									bounce('bad amount spent by peer: ' || $transferredFromPeer);
```
