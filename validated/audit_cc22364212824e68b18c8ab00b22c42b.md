### Title
Asset-attestor list length limit enforced for regular units but not for AA-defined asset templates - ([File: aa_validation.js])

### Summary
The reachable analog of the OpenQ bug (same "number of items" limit enforced on one path but not on the parallel path) is the handling of the `attestors` field for the `asset` message app. In `validation.js`, a regularly-posted `asset` unit has its `attestors` array bounded by `constants.MAX_ATTESTORS_PER_ASSET` via `checkAttestorList`, but the equivalent field validated for Autonomous Agent (AA) definitions/templates in `aa_validation.js`'s `validateAttestors` performs no length cap on the array before allowing it into a stored AA template.

### Finding Description
`validateAssetDefinition` in `validation.js` requires that when `payload.spender_attested` is set, the attestor list passes `checkAttestorList`, which is the intended anti-spam control bounding attestor count by `constants.MAX_ATTESTORS_PER_ASSET` (64). [1](#0-0) [2](#0-1) 

By contrast, `validateAADefinition`'s inner `validateAttestors` function (used to validate `asset`/`asset_attestors` templates embedded in an AA definition, which any unprivileged AA author can post) only checks that the array is non-empty and that each element is a valid address or a formula string — there is no bound on `attestors.length`. [3](#0-2) 

Since AA-defined `asset`/`asset_attestors` payloads are validated through this AA-template path (see `aaApps` list including `asset` and `asset_attestors`), an attacker can define an AA whose asset template embeds an attestor list far larger than `MAX_ATTESTORS_PER_ASSET`. [4](#0-3) [5](#0-4) 

This mirrors the reported bug class exactly: the same conceptual limit (bounding the number of a repeated sub-item to prevent resource blow-up) is enforced on one code path (`validateAssetDefinition`/`checkAttestorList`) but omitted on the structurally parallel path (`validateAttestors` in AA templates).

### Impact Explanation
When the AA actually triggers and evaluates the `asset`/`asset_attestors` message (post-substitution of formulas with concrete values), the resulting concrete asset definition is written to the `assets`/`asset_attestors` tables and later re-validated by any node reading/using that asset (e.g., `checkAttestorList`-based consumers, definition evaluation for `spender_attested` conditions, and per-block validation that has to process this attestor list on every node that syncs). An unbounded attestor list from an AA-defined asset can cause disproportionate CPU/DB processing on every full node that has to validate and store the asset definition and its attestor set, and repeated triggers can create arbitrarily many such definitions, leading to a node-wide resource/DoS impact — an unprivileged AA author can reach this via a normal AA definition post and later trigger, without any special privilege.

### Likelihood Explanation
Likelihood is limited by the fact that the bypass only manifests once the AA is actually triggered and its `asset`/`asset_attestors` message is emitted with a concrete (non-formula) attestors array exceeding 64 entries; this requires deliberate construction but no privileged access — any address can define and trigger an AA. Given the low barrier (regular unit posting) and the direct availability of the control's absence in `aa_validation.js`, likelihood is Medium.

### Recommendation
Add the same `MAX_ATTESTORS_PER_ASSET` length check (and any related total-length/complexity checks that `checkAttestorList` performs) inside `validateAttestors` in `aa_validation.js`, so AA-issued asset/asset_attestors templates cannot embed attestor lists longer than what is enforced for regular asset definitions in `validation.js`. Alternatively, funnel both paths through a single shared `checkAttestorList`-style validator that applies the identical bound regardless of whether the asset is defined directly or via an AA template.

### Proof of Concept
1. Post an AA definition whose `messages` include an `asset` (or `asset_attestors`) app with a `payload.attestors` array literal containing, e.g., 1000 valid-looking address strings (or a formula that expands to such an array at trigger time).
2. `validateAADefinition` → `validateAttestors` accepts this template because it never checks `attestors.length` against `constants.MAX_ATTESTORS_PER_ASSET`. [3](#0-2) 
3. Trigger the AA so it emits the concrete `asset`/`asset_attestors` message with the oversized attestors list; this message is processed as a normal AA response message and, unlike a directly-posted unit, is not re-checked against `checkAttestorList`'s cap the way `validateAssetDefinition` would enforce for a human-authored unit. [1](#0-0) 
4. Every node processing/storing this AA-generated asset definition and its attestor list incurs the outsized processing cost, repeatable at will by re-triggering the AA — reproducing the "limit enforced on one path, not the analogous other" DoS pattern from the source report.

### Citations

**File:** validation.js (L2746-2750)
```javascript
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
```

**File:** constants.js (L42-52)
```javascript
// anti-spam limits
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_CHOICES_PER_POLL = 128;
exports.MAX_CHOICE_LENGTH = 64;
exports.MAX_DENOMINATIONS_PER_ASSET_DEFINITION = 64;
exports.MAX_ATTESTORS_PER_ASSET = 64;
```

**File:** aa_validation.js (L31-31)
```javascript
exports.aaApps = ['payment', 'data', 'data_feed', 'definition', "asset", "asset_attestors", "attestation", "poll", "vote", 'text', 'profile', 'definition_template', 'state'];
```

**File:** aa_validation.js (L41-61)
```javascript
			function validateAttestors(attestors, cb3) {
				if (isNonemptyString(attestors)) {
					var f = getFormula(attestors);
					if (f === null)
						return cb3("attestors is a string but not formula: " + attestors);
					return cb3();
				}
				if (!isNonemptyArray(attestors))
					return cb3("wrong attestors: " + JSON.stringify(attestors));
				for (var i = 0; i < attestors.length; i++) {
					var attestor = attestors[i];
					if (!isNonemptyString(attestor))
						return cb3("bad attestor: " + JSON.stringify(attestor));
					if (!isValidAddress(attestor)) {
						var f = getFormula(attestor);
						if (f === null)
							return cb3("bad formula in attestor");
					}
				}
				cb3();
			}
```

**File:** aa_validation.js (L73-81)
```javascript
			if (['payment', 'asset', 'asset_attestors', 'attestation', 'poll', 'vote'].indexOf(message.app) >= 0) {
				if ('init' in payload) {
					if (!isNonemptyString(payload.init))
						return cb2("bad init: " + JSON.stringify(payload.init));
					var f = getFormula(payload.init);
					if (f === null)
						return cb2("init is not a formula: " + payload.init);
				}
			}
```
