Confirmed: `is_valid_signed_package` in `formula/evaluation.js` allows an AA to accept an off-chain-signed package with no lower bound on staleness — exactly the bug class in the report.

### Title
AA off-chain price/order verification via `is_valid_signed_package` has no lower-bound freshness check, allowing replay of arbitrarily old signed data - (File: formula/evaluation.js)

### Summary
`is_valid_signed_package(signedPackage, address)` is the ocore primitive AA authors use to verify externally-signed messages (e.g. signed price feeds, signed orders) posted as AA trigger data. Its only recency check is that the `last_ball_unit` embedded in the package is not from the future relative to the current evaluation MCI. There is no check that the package is not extremely old.

### Finding Description
`case 'is_valid_signed_package'` [1](#0-0)  validates a signed package as follows: it resolves `signedPackage.last_ball_unit` and only rejects it if `row.main_chain_index > mci` (the last ball is in the future) or not on the main chain; it never checks that `main_chain_index` (or `signedPackage.timestamp`, if present) is *recent enough*. It then calls `signed_message.validateSignedMessage`, which likewise only checks that `last_ball_mci > mci` should fail, never enforcing any minimum age [2](#0-1) . So a signed package that was valid (and signed) months or years ago, referencing an old but still-known `last_ball_unit`, remains "valid" forever as far as `is_valid_signed_package` is concerned — this is structurally identical to the reported bug where the signature-timestamp check `priceSig.timestamp <= liquidationTimestamp + liquidationTimeout` only bounds the signature from being too new, never rejecting it for being too old.

This primitive is explicitly intended for oracle-style/price/order verification use cases in AAs, as shown by the shipped sample AA `test/samples/order_book_exchange.oscript`, which calls `is_valid_signed_package(trigger.data.order1, $order1.address)` to authenticate a signed limit order (price + amount) submitted by any unprivileged trigger sender, and even contains the comment `// to do check expiry` acknowledging that no freshness check is implemented [3](#0-2) . Because `is_valid_signed_package` itself provides no freshness guarantee, any AA relying on it to authenticate time-sensitive off-chain data (prices, orders, rates) must independently re-derive and check `signedPackage.timestamp` against the current AA-visible `timestamp`; the primitive gives no built-in protection, and the codebase's own reference implementation omits this check.

### Impact Explanation
An unprivileged trigger sender (any user, playing the role of "liquidator"/counterparty in the analog) can submit a trigger carrying a stale-but-once-validly-signed package (e.g., an old, favorable exchange rate or order price signed by a legitimate counterparty/oracle) to an AA built on this primitive. If the AA logic does not itself layer an explicit `timestamp`/expiry check, `is_valid_signed_package` will still return `true`, letting the sender force settlement/trade execution at an outdated price. This can lead to loss of AA funds or unfair value extraction from other AA participants (e.g., the counterparty whose order gets matched against a stale price, or the AA's balance being drained via a favorable stale rate), matching the "AA fund loss" impact class.

### Likelihood Explanation
Medium-High: reaching this requires only posting an ordinary AA trigger unit with attacker-chosen `trigger.data` containing a previously captured signed package — no special privilege, no compromised keys, and no network-level manipulation. The vulnerability is latent in any AA that follows the documented/shipped usage pattern of `is_valid_signed_package` for price/order authentication without adding its own staleness check, and the codebase's own sample AA demonstrates exactly this gap.

### Recommendation
Either (a) have `is_valid_signed_package` optionally accept a `max_age`/`min_mci` parameter and reject packages whose `last_ball_unit` MCI (or `signedPackage.timestamp`) is older than that bound, giving AA authors a built-in, hard-to-forget freshness guard; or (b) explicitly document that `is_valid_signed_package` provides no staleness guarantee and that any timestamp field inside `signed_message` must be independently checked by the AA against `timestamp`/`last_ball_timestamp`, and update the shipped sample AA (`order_book_exchange.oscript`) to implement the "to do check expiry" it currently omits, so it isn't propagated as a template for real deployments.

### Proof of Concept
1. Oracle/counterparty signs a package at time T0 containing `{signed_message: {price: 100}, last_ball_unit: U0}` via `signMessage` [4](#0-3) , where `U0` is stable at MCI `m0`.
2. Time passes; the true price has moved far from 100, but `U0` remains a valid, stable unit with `main_chain_index m0 <= current mci`.
3. An attacker posts an AA trigger at current MCI `mci >> m0` with `trigger.data.order = {signed_message:{price:100}, last_ball_unit:U0, authors:[...]}`.
4. The AA's `if` condition calls `is_valid_signed_package(trigger.data.order, oracle_address)`; the check `row.main_chain_index > mci` is false (m0 <= mci), so the package passes [5](#0-4) , and `validateSignedMessage` similarly imposes no minimum-age bound [6](#0-5) .
5. The AA executes trade/settlement logic using the stale `price: 100`, exactly as the shipped `order_book_exchange.oscript` sample would do since it has no expiry check [7](#0-6) .

### Citations

**File:** formula/evaluation.js (L1653-1702)
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
					});
				});
				break;
```

**File:** signed_message.js (L28-112)
```javascript
function signMessage(message, from_address, signer, bNetworkAware, handleResult){
	if (typeof bNetworkAware === 'function') {
		handleResult = bNetworkAware;
		bNetworkAware = false;
	}
	var objAuthor = {
		address: from_address,
		authentifiers: {}
	};
	var objUnit = {
		version: constants.version,
		signed_message: message,
		authors: [objAuthor]
	};
	
	function setDefinitionAndLastBallUnit(cb) {
		if (bNetworkAware) {
			composer.composeAuthorsAndMciForAddresses(db, [from_address], signer, function (err, authors, last_ball_unit) {
				if (err)
					return handleResult(err);
				objUnit.authors = authors;
				objUnit.last_ball_unit = last_ball_unit;
				cb();
			});
		}
		else {
			signer.readDefinition(db, from_address, function (err, arrDefinition) {
				if (err)
					throw Error("signMessage: can't read definition: " + err);
				objAuthor.definition = arrDefinition;
				cb();
			});
		}
	}

	var assocSigningPaths = {};
	signer.readSigningPaths(db, from_address, function(assocLengthsBySigningPaths){
		var arrSigningPaths = Object.keys(assocLengthsBySigningPaths);
		assocSigningPaths[from_address] = arrSigningPaths;
		for (var j=0; j<arrSigningPaths.length; j++)
			objAuthor.authentifiers[arrSigningPaths[j]] = repeatString("-", assocLengthsBySigningPaths[arrSigningPaths[j]]);
		setDefinitionAndLastBallUnit(function(){
			var text_to_sign = objectHash.getSignedPackageHashToSign(objUnit);
			async.each(
				objUnit.authors,
				function(author, cb2){
					var address = author.address;
					async.each( // different keys sign in parallel (if multisig)
						assocSigningPaths[address],
						function(path, cb3){
							if (signer.sign){
								signer.sign(objUnit, {}, address, path, function(err, signature){
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
						},
						function(err){
							cb2(err);
						}
					);
				},
				function(err){
					if (err)
						return handleResult(err);
					console.log(require('util').inspect(objUnit, {depth:null}));
					handleResult(null, objUnit);
				}
			);
		});
	});
}
```

**File:** signed_message.js (L255-301)
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
```

**File:** signed_message.js (L1693-1699)
```javascript

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
