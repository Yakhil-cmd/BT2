This confirms the vulnerability class directly. I have enough evidence to produce the finding.

### Title
Off-chain signed orders (`is_valid_signed_package`) lack expiry/context binding, allowing stale order replay against a signer's will - (File: test/samples/order_book_exchange.oscript, formula/evaluation.js, signed_message.js)

### Summary
`is_valid_signed_package()` / `is_valid_sig()` in `formula/evaluation.js` and the underlying `signed_message.validateSignedMessage()` only verify that a `signed_message` object was signed by a claimed address and (optionally) that its `last_ball_unit` is stable; they enforce no expiry, no destination-AA binding, and no consumption/nonce marking of their own [1](#0-0) . This mirrors exactly the `TermAuth` design flaw described in the external report: an off-chain authorization token that is not bound to a specific transaction, destination contract, or expiry, so it remains valid indefinitely and can be submitted by *any* address (not just the signer) to authorize an action the signer no longer consents to.

### Finding Description
`is_valid_signed_package` evaluates a `signed_message`/`authors` package and defers all replay/expiry protection to whichever AA consumes it [2](#0-1) . The reference AA template shipped in the codebase, `order_book_exchange.oscript`, is the trust-boundary consumer: any user can post a trigger containing two previously-obtained signed orders (`trigger.data.order1`, `trigger.data.order2`) authored by two different addresses, and the AA will execute the trade as long as `is_valid_signed_package` passes and an `executed_` state flag has not been set [3](#0-2) . Critically, the code contains the literal comment `// to do check expiry` — expiry is never enforced [4](#0-3) . The order's identity/nonce (`$id1`, `$id2`) is derived only from the order content and `last_ball_unit`, not from any destination AA address or timestamp, and the "used" flag (`var['executed_'||$id]`) is local per-AA-address storage [5](#0-4) . `signed_message.js`'s `validateSignedMessage` only checks that `last_ball_unit` is stable and not in the future relative to mci; it does not check any application-level expiry or that the message was meant only for a particular contract [6](#0-5) .

This is structurally identical to the reported bug class: a party creates and hands over an authenticating signature (here, a signed limit order) intended to authorize one specific, time-bound trade; because the primitive carries no expiry and no binding to a specific destination/contract instance, that same signature remains perpetually replayable by any holder — including a counterparty who chooses to wait and later submit it once market conditions changed in their favor, executing a stale trade the signer never intended to allow to persist that long.

### Impact Explanation
An attacker (any user reachable via a normal trigger — no privileged keys needed) who has obtained a copy of a previously valid signed order (e.g. from a prior failed matching attempt, a leaked/shared quote, or a counterparty who received but did not execute it) can replay it at an arbitrary future time to force execution of the order at the original stale price/amount, causing the original signer's AA-held balance to be moved into a trade they no longer intend to honor. Because the order's replay-nonce is derived only from its own content, the same signed order can also be resubmitted against any other identically-coded AA instance where the signer happens to hold a balance, since the "used" flag is stored separately per AA address and the signature carries no per-destination binding. This results in unauthorized asset transfer/AA fund loss for the signer, consistent with "concrete AA fund loss" impact criteria.

### Likelihood Explanation
High for any deployer/user of this reference exchange pattern: the sample AA is shipped directly in the ocore codebase as a documented reference for `is_valid_signed_package` usage and is exercised in the test suite [7](#0-6) , so any AA author following this pattern inherits the flaw by default; the core primitive itself provides no expiry/binding safety net to fall back on.

### Recommendation
Extend `is_valid_signed_package`/`is_valid_sig` semantics (or strongly document the requirement) so that any oscript relying on off-chain signed authorization must include, inside the signed payload itself, an explicit expiry timestamp, the intended destination AA address (`this_address`), and a nonce, and must verify all three before consuming the message — mirroring the pattern already correctly used in `payment_channels.oscript` (`channel != this_address`, `period != var['period']`) [8](#0-7) . Update `order_book_exchange.oscript` to check `$order1.expiry`/`$order2.expiry` against `timestamp` and to bind orders to `this_address` before matching.

### Proof of Concept
1. Alice signs an order package `order1 = {signed_message: {address: Alice, sell_asset: X, buy_asset: Y, sell_amount: 100, price: 1, ...}}` off-chain, intending it to be filled promptly on exchange AA `E`.
2. Bob, holding a copy of `order1` (e.g. shared during negotiation, or observed in an earlier bounced trigger), waits until market prices move against Alice.
3. Bob submits a trigger to AA `E` with `trigger.data.order1 = order1` and his own matching `order2`. `is_valid_signed_package` still validates because the signature never expires and is not scoped to a time window [9](#0-8) .
4. The trade executes at Alice's stale price since `order_book_exchange.oscript` never checks expiry (`// to do check expiry`) [4](#0-3) , moving funds from Alice's AA balance without her present consent.

### Citations

**File:** formula/evaluation.js (L1666-1699)
```javascript
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

**File:** formula/evaluation.js (L1704-1721)
```javascript
			case 'is_valid_sig':
				var message = arr[1];
				var pem_key = arr[2];
				var sig = arr[3];
				evaluate(message, function (evaluated_message) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isNonemptyString(evaluated_message))
						return setFatalError("bad message string in is_valid_sig", { arr }, false, cb);
					evaluate(sig, function (evaluated_signature) {
						if (fatal_error)
							return cb(false);
						if (!ValidationUtils.isNonemptyString(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
						if (evaluated_signature.length > 1024)
							return setFatalError("signature is too large", { arr }, false, cb);
						if (!ValidationUtils.isValidHexadecimal(evaluated_signature) && !ValidationUtils.isValidBase64(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
```

**File:** test/samples/order_book_exchange.oscript (L27-49)
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

**File:** test/ojson.test.js (L1249-1252)
```javascript
test('Order book exchange', t => {
	var ojson = readSample('order_book_exchange.oscript')
	parseOjson(ojson, (err, res) => { t.deepEqual(err || res,
		[
```

**File:** test/samples/payment_channels.oscript (L104-112)
```text
				if: `{ trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer }`,
				init: `{
					$bInitiatedByA = (var['close_initiated_by'] == 'A');
					if (trigger.data.sentByPeer.signed_message.channel != this_address)
						bounce('signed for another channel');
					if (trigger.data.sentByPeer.signed_message.period != var['period'])
						bounce('signed for a different period of this channel');
					if (!is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB))
						bounce('invalid signature by peer');
```
