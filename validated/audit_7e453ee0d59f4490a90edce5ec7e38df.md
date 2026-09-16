### Title
Signature-Replay Risk via `is_valid_signed_package()` Lacking Built-in Context Binding - ([File: formula/evaluation.js])

### Summary
The Obyte AA formula operator `is_valid_signed_package()` (and its underlying primitive `signed_message.validateSignedMessage()`) verifies only that a `signed_message` package was signed by a specified address — it performs no binding of the signed content to the specific AA instance, position, or purpose that consumes it. This is structurally analogous to the Atomic Green incident, where a single manager signature intended for one LP position could be replayed across 21 different positions because the signature format did not encode which position it authorized.

### Finding Description
`is_valid_signed_package` in `formula/evaluation.js` evaluates an address expression and a signed-package expression, then delegates to `signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, cb)`: [1](#0-0) 

`validateSignedMessage` checks that the package is well-formed, that the specified `address` actually signed it, and that the signature verifies against the address's definition — but it imposes no constraint on the semantic content of `signed_message` itself, nor any anti-replay/nonce mechanism scoped to the calling AA or a particular sub-object (e.g., a specific position, order, or channel): [2](#0-1) [3](#0-2) 

The protocol places full responsibility on the AA author to embed a unique, unambiguous binding value inside `signed_message` (e.g., channel id, period, position id) and to explicitly check it in oscript logic. The bundled `payment_channels.oscript` sample demonstrates the required manual mitigation — checking `signed_message.channel` and `signed_message.period` before trusting a peer's signed package: [4](#0-3) 

If an AA author building a leveraged-trading or multi-position protocol (structurally the same class as Atomic Green) uses `is_valid_signed_package(trigger.data.managerSig, $managerAddress)` to authorize privileged actions (e.g., burn/withdraw) on a shared or per-position state without embedding a position/LP-identifier inside the signed payload and validating it against `trigger.data`/state vars, the exact same signed package remains valid for every AA instance or state permutation that trusts `$managerAddress`. An unprivileged trigger sender who obtains one manager-signed package (e.g., by observing it on-chain or via a prior authorized trigger) can resubmit it as `trigger.data` to other AA instances/positions sharing the same manager address, since `is_valid_signed_package` re-validates successfully every time — there is no unit-level or protocol-level replay protection for signed packages, only whatever the AA’s own oscript logic enforces.

### Impact Explanation
Any AA design that relies on `is_valid_signed_package` for privileged, per-position or per-object authorization (loan/vault management, LP position operations, channel-closing, order execution) without independently embedding and checking a unique target identifier is exposed to cross-instance signature replay, allowing an unprivileged AA trigger sender to trigger unauthorized fund movement/state transitions across multiple positions authorized by the same signer — mirroring the $29,984.27 loss caused by cross-position replay in the Atomic Green incident. This is a Medium-severity, fund-loss-capable class of AA vulnerability directly enabled by the missing built-in context binding in the primitive.

### Likelihood Explanation
Likelihood is Medium: exploitation requires a vulnerable AA design pattern (multiple AA instances/positions trusting the same signer without binding data), which is a realistic and common pattern for multi-position leveraged/trading protocols on Obyte, exactly as seen with Atomic Green on a comparable chain. The core primitive itself does not prevent this misuse, so the risk surfaces whenever an unprivileged AA trigger sender can obtain and replay a previously valid signed package.

### Recommendation
- Document and, where feasible, enforce that AA authors embed a unique, application-scoped identifier (e.g., `this_address`, position id, nonce, expiry) inside every `signed_message` verified via `is_valid_signed_package`, and require the AA to check that identifier against trigger/state data before trusting the package, following the pattern already used in `test/samples/payment_channels.oscript`.
- Consider adding an optional built-in binding parameter to `is_valid_signed_package`/`validateSignedMessage` (e.g., automatically hashing in `this_address` or a caller-supplied context string) so that signed packages are cryptographically bound to the specific AA/context by default rather than relying entirely on AA-author discipline.

### Proof of Concept
1. Deploy AA `Manager` at address `M`.
2. Deploy AA instances `Position1` and `Position2`, both configured to trust manager address `M` and both accepting a trigger data field `sentByManager` (a signed package), calling `is_valid_signed_package(trigger.data.sentByManager, $managerAddress)` to authorize a withdrawal/burn action, without checking any position-specific field inside `signed_message`.
3. Manager signs one package: `{ signed_message: { action: 'burn' }, authors: [...] }` intended to authorize burn on `Position1`.
4. Attacker (unprivileged trigger sender) observes this signed package (it is posted in a unit and publicly visible) and resubmits it verbatim as `trigger.data.sentByManager` to `Position2`.
5. `Position2`'s AA formula calls `is_valid_signed_package(...)`, which succeeds (correct signer, correct address, well-formed package) since nothing in the primitive or the AA (in this vulnerable design) binds the package to `Position1` specifically.
6. `Position2` executes the unauthorized burn/withdrawal, replaying the manager's single signature across a second, unrelated position — same root cause as the Atomic Green exploit.

### Citations

**File:** formula/evaluation.js (L1661-1699)
```javascript
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

**File:** signed_message.js (L117-182)
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
	if (!the_author) {
```

**File:** signed_message.js (L255-302)
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
```

**File:** test/samples/payment_channels.oscript (L103-119)
```text
			{ // fraud proof
				if: `{ trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer }`,
				init: `{
					$bInitiatedByA = (var['close_initiated_by'] == 'A');
					if (trigger.data.sentByPeer.signed_message.channel != this_address)
						bounce('signed for another channel');
					if (trigger.data.sentByPeer.signed_message.period != var['period'])
						bounce('signed for a different period of this channel');
					if (!is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB))
						bounce('invalid signature by peer');
					$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
					if ($transferredFromPeer < 0)
						bounce('bad amount spent by peer: ' || $transferredFromPeer);
					$transferredFromPeerAsClaimedByPeer = var['spentBy' || ($bInitiatedByA ? 'A' : 'B')];
					if ($transferredFromPeer <= $transferredFromPeerAsClaimedByPeer)
						bounce("the peer didn't lie in his favor");
				}`,
```
