### Title
`is_valid_signed_package`/`validateSignedMessage` freshness ("nonce") check is silently skipped when `last_ball_unit` is omitted, enabling unlimited replay of signed oracle/price packages - (File: formula/evaluation.js, signed_message.js)

### Summary
`is_valid_signed_package` (oscript) and the underlying `signed_message.validateSignedMessage()` use the optional `last_ball_unit` field of a `signed_package` as the freshness/anti-replay anchor (analogous to an OIDC `nonce`): when present, it is checked against a specific stable MCI; when absent, the whole freshness binding is skipped and the signature is validated against the *current* evaluation MCI instead, causing the check to always pass. An attacker who controls the AA trigger data can strip `last_ball_unit` from an old, legitimately-signed package and resubmit it to an AA at any later time; the AA will treat it as freshly valid.

### Finding Description
In `formula/evaluation.js`, `is_valid_signed_package` only bounds the package to the DAG when `last_ball_unit` is a string: [1](#0-0) 

If `last_ball_unit` is omitted, none of that block executes and the code proceeds straight to `signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, ...)`.

Inside `validateSignedMessage`, "network awareness" is derived purely from field presence: [2](#0-1) 

When `last_ball_unit` is absent, `bNetworkAware` is `false`, and `validateOrReadDefinition` takes the `else` branch, which never looks at the DAG or any timestamp/ball at all - it just checks that a supplied `definition` hashes to the author address, and returns `last_ball_mci = mci` (the *current* evaluation MCI) rather than the MCI the message was actually signed at: [3](#0-2) 

Back in `evaluation.js`, the final freshness gate is:
```
if (last_ball_mci === null || last_ball_mci > mci) return cb(false);
cb(true);
```
Since `last_ball_mci` was just set to `mci`, `last_ball_mci > mci` is always false, so the call always resolves to `true`, regardless of when the signature was originally produced. There is no other timestamp/nonce/counter binding the signature to a point in time in this code path.

This is structurally the same bug class as the reported Logto issue: a field meant to bind a signed credential to a specific context (`nonce` in the OIDC id_token / `last_ball_unit` here) is validated *only if present*; an attacker simply omits it and the anti-replay check is bypassed entirely instead of being enforced or rejected as missing.

### Impact Explanation
Many AAs use `is_valid_signed_package` (or `signed_message.validateSignedMessage` directly) to authenticate off-chain-signed data supplied by a trigger sender - most commonly price/oracle attestations, KYC/whitelist attestations, or exchange-order signatures (see `test/samples/order_book_exchange.oscript`, `test/samples/payment_channels.oscript`). Because the freshness check silently no-ops when `last_ball_unit` is stripped, any unprivileged AA trigger sender can:
1. Capture any previously-published signed package from the legitimate signer (e.g., an old, favorable price quote or an expired authorization).
2. Strip the `last_ball_unit` field and resubmit it in a new AA trigger at any time in the future.
3. Have the AA accept it as a fresh, currently-valid signature, since `is_valid_signed_package` returns `true`.

Depending on how the AA uses the verified content, this enables replay of stale price/oracle data or stale authorizations against an AA, leading to AA fund loss (e.g., trading against an outdated price) or bypass of time-limited authorizations — squarely matching the "concrete AA fund loss" impact bar.

### Likelihood Explanation
Any unprivileged AA trigger sender can craft `trigger.data.signed_package` arbitrarily; simply omitting one JSON field (`last_ball_unit`) is trivial and requires no special access, no cooperation from the hub/other nodes, and no waiting period. The only prerequisite is that a target AA relies on `is_valid_signed_package`/`validateSignedMessage` for authenticating externally-signed data without itself re-implementing an independent freshness check (a reasonable design assumption given the function's name and the presence of a dedicated `last_ball_unit` freshness parameter).

### Recommendation
Do not allow `bNetworkAware`/freshness validation to be skipped based on field presence. Either:
- Require `last_ball_unit` (and enforce the MCI bound) unconditionally in `signed_message.validateSignedMessage` and `is_valid_signed_package`, rejecting packages that omit it, or
- If an "offline" mode without `last_ball_unit` is intentionally supported, make sure the returned `last_ball_mci` cannot be conflated with "as fresh as the current MCI" — e.g., return a value that fails any subsequent freshness comparison, and require AA authors to explicitly opt into stale-signature acceptance rather than silently defaulting to it.

### Proof of Concept
1. Signer signs a package legitimately with `last_ball_unit` set to unit U at MCI 100 (e.g., a price quote): `{signed_message, authors, last_ball_unit: U}`.
2. Time passes; MCI advances far beyond 100.
3. Attacker (any AA trigger sender) copies the signed package but deletes the `last_ball_unit` field, keeping `signed_message`, `authors` (with valid `definition`/`authentifiers`) intact.
4. Attacker sends a trigger to the target AA with `trigger.data.signed_package` = the stripped package.
5. AA formula calls `is_valid_signed_package(trigger.data.signed_package, address)`; since `last_ball_unit` is absent, the MCI-bound freshness check in `formula/evaluation.js` (lines 1684-1692) is skipped, and `signed_message.validateSignedMessage` returns `last_ball_mci = mci` (current), so `last_ball_mci > mci` is false ⇒ the call returns `true`.
6. The AA treats the stale, replayed signed package as freshly authenticated, acting on outdated data (e.g., executing a trade at the old price), causing fund loss.

### Citations

**File:** formula/evaluation.js (L1672-1699)
```javascript
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

**File:** signed_message.js (L193-195)
```javascript
	var bNetworkAware = ("last_ball_unit" in objSignedMessage);
	if (bNetworkAware && !ValidationUtils.isValidBase64(objSignedMessage.last_ball_unit, constants.HASH_LENGTH))
		return handleResult("invalid last_ball_unit");
```

**File:** signed_message.js (L241-252)
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
```
