### Title
Missing deadline/expiration enforcement in signed message verification allows unlimited replay of off-chain signatures - (File: signed_message.js)

### Summary
`signed_message.js`'s `validateSignedMessage()` — the routine backing the `is_valid_signed_package()` oscript primitive used by AAs to verify externally-signed messages (e.g. signed orders, price quotes, off-chain approvals) — accepts an optional `timestamp` field but never validates it against the current time, the trigger's timestamp, or any expiration window. A signed package therefore remains valid forever, exactly matching the reported "lifetime license" signature class of bug.

### Finding Description
`validateSignedMessage()` only allows a fixed set of fields (`"signed_message", "authors", "last_ball_unit", "timestamp", "version"`) and performs structural/signature checks, but the `timestamp` field is never read or compared against anything: [1](#0-0) 

The function verifies the signature cryptographically via `Definition.validateAuthentifiers` and, when `last_ball_unit` is present, ensures that unit is stable, but nowhere does it check whether the signed package has expired: [2](#0-1) 

This function is invoked directly by the `is_valid_signed_package` oscript operator, which AA authors use to validate externally supplied signed packages inside `trigger.data`: [3](#0-2) 

The bundled sample AA `order_book_exchange.oscript`, which implements signed off-chain order matching using `is_valid_signed_package`, explicitly flags this gap with a `// to do check expiry` comment right where signed orders are validated — confirming that the framework provides no expiration primitive and leaves it entirely to the AA author to remember to add one: [4](#0-3) 

### Impact Explanation
Any AA that relies on `is_valid_signed_package()`/`validateSignedMessage()` to authorize an action based on an off-chain signed message (order, price quote, permission grant, etc.) without independently embedding and checking an expiry field in the signed payload will accept that signature indefinitely. An attacker who obtains an old signed package (e.g., a stale price quote, an old order, or a previously valid but now-outdated approval) can replay it against the AA at any future time to trigger unintended fund transfers, mis-priced trades, or stale authorization — i.e., unauthorized spending / AA fund loss, since the framework offers no deadline enforcement and a naive or rushed AA author has no built-in protection.

### Likelihood Explanation
Likelihood is medium-to-high: this is a framework-level gap, not a one-off application bug — any single AA that uses `is_valid_signed_package` for financial logic (as the shipped `order_book_exchange.oscript` sample does) is affected unless the AA author manually adds and validates an expiry field inside `signed_message`. Since the sample code itself has a "to do check expiry" placeholder rather than an actual check, it demonstrates how easy it is to omit this safeguard in production AAs, and the trigger sender fully controls when to submit the (still-valid) old signed package.

### Recommendation
Add first-class deadline support to `signed_message.js`: interpret the existing `timestamp` field (or add an `expiry_ts`) as an expiration bound and reject the package in `validateSignedMessage()` if the current unit/trigger time (or `last_ball_timestamp`) exceeds it, similar to how `last_ball_unit` staleness is already checked. At minimum, document/require that any AA relying on `is_valid_signed_package` for value-bearing logic must independently enforce an expiry field inside `signed_message`, and update the shipped sample (`order_book_exchange.oscript`) to implement the expiry check instead of leaving a "to do" placeholder, since it is used as a reference implementation for third-party AA authors.

### Proof of Concept
1. Alice signs an order via `signMessage()` with `signed_message: {price: 100, ...}` and no expiry field, producing `objSignedPackage`.
2. Market conditions change drastically over time (e.g., months later).
3. An adversary (or Alice's counterparty) submits `objSignedPackage` unchanged as `trigger.data.order1` to the `order_book_exchange` AA.
4. The AA calls `is_valid_signed_package(trigger.data.order1, $order1.address)`, which internally calls `signed_message.validateSignedMessage()`; since no deadline is checked at [5](#0-4) , the stale signature is accepted as fully valid, and the trade executes at the outdated price, causing Alice a loss she never intended to accept at the time of execution.

### Citations

**File:** signed_message.js (L130-137)
```javascript
	if (!ValidationUtils.isNonemptyObject(objSignedMessage))
		return handleResult("signed message must be a non-empty object");
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
```

**File:** signed_message.js (L277-295)
```javascript
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
```

**File:** formula/evaluation.js (L1653-1701)
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
```

**File:** test/samples/order_book_exchange.oscript (L31-49)
```text
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
