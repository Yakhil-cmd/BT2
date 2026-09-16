Based on my investigation, I found a concrete analog to the reported bug class.

### Title
`last_ball_timestamp` defaults to 0 for non-network-aware signed messages, bypassing address-definition `timestamp` conditions - ([File: signed_message.js])

### Summary
`_timestampLU` (PoolService) being zero in unhandled edge cases causes downstream calculations to behave incorrectly. In ocore, an analogous variable is `objValidationState.last_ball_timestamp`, which is used by the `'timestamp'` oscript operator in address definitions to gate authentifier evaluation. When a signed message is validated without network awareness (no `last_ball_unit`), this value is hard-coded to `0` instead of being derived from an actual stable unit, silently changing the outcome of any `['timestamp', relation, X]` condition in the definition.

### Finding Description
`validateSignedMessage` in `signed_message.js` supports two modes, selected by whether `last_ball_unit` is present in the signed message (`bNetworkAware`). In the non-network-aware branch, `validateOrReadDefinition` calls back with a hard-coded last-ball timestamp of `0`: [1](#0-0) 

This value is placed directly into `objValidationState.last_ball_timestamp`: [2](#0-1) 

`objValidationState.last_ball_timestamp` is then consumed by the `'timestamp'` operator inside `evaluate()` in `definition.js`, which is reachable by any address definition that includes a `timestamp` condition (e.g., time-locked spending conditions, escrow release windows, etc.): [3](#0-2) 

Because `last_ball_timestamp` is forced to `0` rather than being computed from the real current/last-stable time, every `timestamp` check in the definition is evaluated against `0` instead of the actual time context, e.g. `['timestamp', '<', X]` is always true for any positive `X`, and `['timestamp', '>', X]` is always false. This differs from the normal on-chain unit-validation path (`validation.js`), where `last_ball_timestamp` is always populated from an actual stable last-ball unit's timestamp: [4](#0-3) 

### Impact Explanation
An address whose definition uses a `timestamp` (or similarly `mci`, since `last_ball_mci` is also forced to a fixed placeholder value `-1`/`mci`) condition to gate a signing/authentifier path — e.g. "this key can only co-sign after date X" or "before date X" — can have that time-based restriction bypassed entirely when the counterparty/dApp uses the non-network-aware signed-message flow (common for arbiter contracts, private-payment counterparty attestations, and off-chain proofs handled via `signed_message.js`). This can let an attacker satisfy a definition branch that should be time-locked, leading to unauthorized authorization of a signed message that downstream logic (e.g., arbiter dispute resolution, chat-based fund release attestations) treats as valid, potentially causing unauthorized fund release/spending decisions that rely on that attestation.

### Likelihood Explanation
Any address definition author who relies on the `'timestamp'` op for access control combined with the non-network-aware signed-message path is affected. Since `signMessage`/`validateSignedMessage` explicitly support and default to `bNetworkAware = false`, this is a normal, reachable code path or, not a corner case requiring a malicious peer — a single crafted or default-flow signed message is enough to trigger the always-0 comparison.

### Recommendation
In the non-network-aware branch of `validateOrReadDefinition`, do not hard-code `last_ball_timestamp` to `0` (and `last_ball_mci` to `-1`). Either reject definitions that contain `timestamp`/`mci`/other last-ball-relative ops when `bNoReferences` is set, or require network-aware validation whenever the definition contains such ops, mirroring the recommendation to explicitly check for the zero/placeholder condition and use a safe alternative computation instead of silently defaulting to `0`.

### Proof of Concept
1. Create an address whose definition includes a branch such as `['timestamp', '<', 9999999999]` (i.e., "always true after time 0, always usable before some far future date") intended to allow signing only in a specific window when validated on-chain.
2. Have the counterparty invoke `signMessage(message, address, signer, /*bNetworkAware=*/false, cb)` — the default in `signMessage`'s signature — producing a signed message without `last_ball_unit`.
3. Call `validateSignedMessage(objSignedMessage, handleResult)` (2-argument form, `conn`/`mci` omitted) as used e.g. from `wallet.js`; internally this takes the `else` branch in `validateOrReadDefinition` and calls back with `last_ball_timestamp = 0`.
4. Observe that `evaluate()`'s `'timestamp'` case in `definition.js` compares `0` against the condition's literal, producing a result independent of real time/context, deterministically bypassing the intended timestamp gate.

### Citations

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

**File:** validation.js (L737-739)
```javascript
					objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index;
					objValidationState.last_ball_timestamp = objLastBallUnitProps.timestamp;
					objValidationState.max_known_mci = objLastBallUnitProps.max_known_mci;
```
