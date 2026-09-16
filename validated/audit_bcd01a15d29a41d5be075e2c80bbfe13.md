### Title
Time/MCI-based Expiry Conditions in Address Definitions Are Silently Bypassed When Verified via `validateSignedMessage()` Without a `last_ball_unit` - (File: signed_message.js)

### Summary
`Definition.validateAuthentifiers()` supports expiry-style guard operators (`mci`, `timestamp`, `age`) inside address/asset definitions, which are evaluated against `objValidationState.last_ball_mci` / `last_ball_timestamp` — values that are supposed to reflect the real, current position in the DAG. In the main unit-validation path (`validation.js`) these values are always derived from the unit's actual `last_ball`/`last_ball_unit`, so an expiry condition like `['mci', ['<', X]]` correctly stops working once the DAG has advanced past `X`. However, `signed_message.js`'s `validateSignedMessage()` — used to validate detached signed packages (e.g. `is_valid_signed_package()` in oscript/AA formulas, arbiter-contract responses, wallet pairing messages) — has a second code path for messages that omit `last_ball_unit` (`bNetworkAware === false`). In that path it hardcodes `last_ball_mci = -1` and `last_ball_timestamp = 0` regardless of the actual current chain state, and none of the `mci`/`timestamp`/`age` evaluation branches are gated by `objValidationState.bNoReferences` (only `has`, `has one`, `seen`, `has equal`, `has one equal`, and `in merkle` are gated). As a result, a signature made under a definition containing an expiry restriction such as `['mci', ['<', X]]` or `['timestamp', ['<', X]]` will always validate as "not yet expired" when submitted without a `last_ball_unit`, no matter how much time/MCI has actually passed — directly analogous to Zitadel's failure to check JWT key expiration in the Authorization Grant flow (a bug-class: security-relevant time/window check bypassed on an alternate verification path).

### Finding Description
- `definition.js` implements the `mci`/`timestamp`/`age` operators purely as comparisons against `objValidationState.last_ball_mci` / `last_ball_timestamp`: [1](#0-0) [2](#0-1) 

- These ops are not covered by the `bNoReferences` guard that protects other reference-dependent ops (`has`, `has one`, `seen`, `has equal`, `in merkle`): [3](#0-2) 

- `signed_message.js` supports validating signed packages both with and without a `last_ball_unit` reference. When `last_ball_unit` is absent (`bNetworkAware` false), it fabricates a static, non-current validation context: [4](#0-3) 

- This fabricated context (`last_ball_mci: -1` or a caller-supplied `mci`, `last_ball_timestamp: 0`) is fed straight into `Definition.validateAuthentifiers`, which evaluates the `mci`/`timestamp` ops against it: [5](#0-4) 

- Since `-1 < X` and `0 < X` are always true, any `['mci', ['<', X]]` or `['timestamp', ['<', X]]` restriction embedded in an address definition — a common way to build a *time-limited signing key/authorization* — is effectively neutralized on this path, letting a key/authorization that should be expired keep validating.
- Reachability: this validation function is invoked from the oscript `is_valid_signed_package()` builtin used inside AA trigger/state formulas, letting any AA author or trigger sender construct a definition + signed package pair (with no `last_ball_unit`) that abuses this bypass: [6](#0-5) 

### Impact Explanation
An AA that relies on `is_valid_signed_package()` to check a counterparty-supplied or self-issued signature for a time-boxed authorization (e.g., "this oracle/relayer key is valid only until MCI X" or "only before timestamp T") can be fed an out-of-window signed package that nonetheless validates as authentic and "in-window," because the `mci`/`timestamp` freshness check is evaluated against fabricated values (`-1`/`0`) rather than the real chain state whenever the trigger's/attacker's payload omits `last_ball_unit`. Depending on how the AA uses the validated package (e.g., releasing funds, updating state, honoring an otherwise-expired price/permission attestation), this can lead to AA fund loss or acceptance of stale/expired authorization data that the contract author explicitly intended to reject after a deadline.

### Likelihood Explanation
The `is_valid_signed_package` formula function and `validateSignedMessage` are reachable by any unprivileged unit poster / AA trigger sender by simply crafting oscript data with a `signed_package` object that has no `last_ball_unit` field — this is not a privileged or peer-only capability. The attacker fully controls the crafted signed package's fields (aside from the definition's actual signature requirement), so the only prerequisite is that a definition with an `mci`/`timestamp` expiry clause exists and is used by the target AA, which is a documented, expected oscript pattern for building expiring authorizations.

### Recommendation
In `signed_message.js`'s non-network-aware branch, either (a) reject definitions containing `mci`/`timestamp`/`age` operators when no `last_ball_unit` is supplied (mirroring the `bNoReferences` treatment already applied to `has`/`seen`/`in merkle`), or (b) require `last_ball_unit` whenever the definition contains such time-sensitive ops so the real, current `last_ball_mci`/`last_ball_timestamp` are used, instead of substituting `-1`/`0`.

### Proof of Concept
1. Create an address definition combining a signature with an expiry clause, e.g.
   `["and", [["sig", {pubkey}], ["mci", ["<", 1000000]]]]`, and derive its address via `objectHash.getChash160`.
2. Sign an arbitrary message under this definition and package it as a `signed_package` object without a `last_ball_unit` field (per `signed_message.js` lines 241-253 handling `bNetworkAware=false`).
3. Have an AA formula call `is_valid_signed_package(pkg, address)` (as in `formula/evaluation.js` lines 1657-1701) well after real chain MCI has passed 1,000,000.
4. Because the validation path fabricates `last_ball_mci=-1` (see `signed_message.js` lines 250-251), the `mci < 1000000` check still evaluates true, and the "expired" signed package is accepted as valid, despite the network having long passed the intended expiry.

### Citations

**File:** definition.js (L480-495)
```javascript
			case 'mci':
			case 'age':
			case 'timestamp':
				if (!isArrayOfLength(args, 2) && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb(op + " must have 2 args");
				var relation = args[0];
				var value = args[1];
				if (!isNonemptyString(relation))
					return cb("no relation");
				if (["=", ">", "<", ">=", "<=", "!="].indexOf(relation) === -1)
					return cb("invalid relation: " + JSON.stringify(relation));
				if (!isNonnegativeInteger(value))
					return cb(op+" must be a non-neg number");
				if (op === 'timestamp' && objValidationState.last_ball_mci < constants.timestampUpgradeMci)
					return cb('timestamp op not allowed yet');
				return cb();
```

**File:** definition.js (L497-501)
```javascript
			case 'has':
			case 'has one':
			case 'seen':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
```

**File:** definition.js (L1036-1048)
```javascript
			case 'timestamp':
				var relation = args[0];
				var timestamp = args[1];
				switch(relation){
					case '>': return cb2(objValidationState.last_ball_timestamp > timestamp);
					case '>=': return cb2(objValidationState.last_ball_timestamp >= timestamp);
					case '<': return cb2(objValidationState.last_ball_timestamp < timestamp);
					case '<=': return cb2(objValidationState.last_ball_timestamp <= timestamp);
					case '=': return cb2(objValidationState.last_ball_timestamp === timestamp);
					case '!=': return cb2(objValidationState.last_ball_timestamp !== timestamp);
					default: throw Error('unknown relation in mci: '+relation);
				}
				break;
```

**File:** signed_message.js (L241-253)
```javascript
		else {
			if (!bHasDefinition)
				return handleResult("no definition");
			try {
				if (objectHash.getChash160(objAuthor.definition) !== objAuthor.address)
					return handleResult("wrong definition: " + objectHash.getChash160(objAuthor.definition) + "!==" + objAuthor.address);
			} catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
			// no last_ball_unit of its own; before the fix, always behave as before (-1) to keep old units re-evaluating the same way
			cb(objAuthor.definition, (mci >= constants.pemCurvesFixMci) ? mci : -1, 0);
		}
	}
```

**File:** signed_message.js (L260-289)
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
```

**File:** formula/evaluation.js (L1684-1699)
```javascript
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
