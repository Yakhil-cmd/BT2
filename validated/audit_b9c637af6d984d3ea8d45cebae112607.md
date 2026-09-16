### Title
Missing network/`alt` (chain-id) binding in `validateSignedMessage` allows cross-network signature replay into `is_valid_signed_package()` — (File: `signed_message.js`)

### Summary
Obyte's `ocore` uses the `alt` field (together with `version`) as the network identifier that plays the same role as Aptos's `chain_id`: it distinguishes mainnet from testnet/devnet and is strictly checked for every DAG unit in `validation.js`. However, the separate "signed message" construct used by `signMessage()` / `validateSignedMessage()` in `signed_message.js` — which is exposed to AA (Autonomous Agent) formulas via `is_valid_signed_package()` — never includes or checks the `alt` field. A signature that is valid on one network is therefore also valid on any other network sharing the same signing/hash algorithm, exactly the "transaction replayed on the wrong chain" bug class described in the report.

### Finding Description
`constants.js` defines the network identifier: [1](#0-0) 

For ordinary DAG units, this is enforced strictly during validation: [2](#0-1) 

But the signed-message code path is separate and does not participate in this check. `signMessage()` builds `objUnit` with only a `version` field, never an `alt` field: [3](#0-2) 

`validateSignedMessage()` restricts the object to the fields `["signed_message", "authors", "last_ball_unit", "timestamp", "version"]` — `alt` is not even an allowed/expected field — and only optionally checks `version` against `supported_versions`, never checking `alt`/network at all: [4](#0-3) 

The rest of the function verifies address definitions and authentifiers (signatures) purely off `objAuthor.address`/`objAuthor.definition`, computed via `getChash160`, which is network-independent: [5](#0-4) 

This `validateSignedMessage` function is reachable from oscript/AA evaluation (`formula/evaluation.js` calls it, most likely backing the `is_valid_signed_package()` oscript function) and from `wallet.js` message-handling code, both confirmed by direct references to `validateSignedMessage` in those files. This means an AA trigger sender (an unprivileged, arbitrary user) can submit a `signed_package` object as part of AA trigger data, and an AA that calls `is_valid_signed_package()` to authorize a payout, confirm an oracle-style attestation, resolve an arbitration decision, or authenticate an off-chain claim will accept a signature that was produced — and is only meant to be valid — on a different network (e.g., testnet), because nothing in the signed structure or its validation binds it to a specific network/chain id.

### Impact Explanation
Any AA (or wallet/API consumer) that relies on `is_valid_signed_package()` / `validateSignedMessage()` to gate value-moving or state-changing logic (fund release, dispute resolution, KYC/attestation-gated actions, exchange order confirmation, etc.) can be tricked into accepting a signature that the signer only produced for/on a different Obyte network. Since users frequently reuse the same seed/keys and address definitions across mainnet and testnet (address derivation via `getChash160` is network-agnostic), an attacker can harvest a signed message a victim produced in a low-stakes context (testnet, a different dApp domain, or a message meant for another purpose) and feed it into a mainnet AA to unlock funds or bypass an authorization check the victim never intended to grant on that network. This is a concrete path to AA fund loss / unauthorized state transition, matching the "unauthorized spending / AA fund loss" impact bar.

### Likelihood Explanation
Medium-High: exploitation requires (1) an AA that uses `is_valid_signed_package`/off-chain signed messages for authorization, and (2) an attacker obtaining a validly-signed message from the victim for a different network/context. Both preconditions are realistic: signed messages are a documented, commonly used primitive in Obyte AAs for oracle attestations and off-chain authorization, and key/address reuse across mainnet/testnet (or across different signing contexts, since there is no domain separator at all) is common because ocore itself provides no mechanism to prevent it.

### Recommendation
Bind every signed message to the network by including the `alt` (and ideally a purpose/domain tag) inside the object that is hashed for signing (`getSignedPackageHashToSign`), and enforce it in `validateSignedMessage`, mirroring the `objUnit.alt !== constants.alt` check already applied to DAG units in `validation.js:277-278`. Concretely:
- Add `alt: constants.alt` to the `objUnit` built in `signMessage()` (`signed_message.js:37-41`).
- In `validateSignedMessage`, extend the allowed-fields list to include `alt` and add a hard check `if (objSignedMessage.alt !== constants.alt) return handleResult("wrong alt");` before authenticator validation (`signed_message.js:132-137`).
- Ensure the `alt` field is part of the payload used by `getSignedPackageHashToSign`, so it cannot be stripped without invalidating the signature.

### Proof of Concept
1. On Obyte testnet (`constants.alt = '2'`), a user signs a message using `signMessage(message, address, signer, true, cb)`, producing `objSignedMessage = { version, signed_message, authors: [{address, authentifiers}], last_ball_unit, timestamp }` — note there is no `alt` field, and the signature covers exactly this object via `objectHash.getSignedPackageHashToSign`.
2. An attacker obtains this `objSignedMessage` (e.g., it was posted publicly, sent to a testnet dApp, or intercepted).
3. The attacker submits the identical `objSignedMessage` JSON as a trigger parameter (`signed_package` in the AA `data`) to a mainnet AA that calls `is_valid_signed_package(signed_package, address)` to gate a payout.
4. `validateSignedMessage` on mainnet computes `getChash160(definition)`/verifies signatures purely from the object contents — since `alt` is neither present nor checked, and `version` alone does not distinguish networks, the mainnet AA accepts the message as valid and executes the authorized action (e.g., releases funds), even though the victim never intended this signature to be valid outside testnet.

### Citations

**File:** constants.js (L21-25)
```javascript
exports.bTestnet = !!process.env.testnet;
console.log('===== testnet = ' + exports.bTestnet);

exports.version = exports.bTestnet ? '4.0t' : '4.0';
exports.alt = exports.bTestnet ? '2' : '1';
```

**File:** validation.js (L275-278)
```javascript
	if (constants.supported_versions.indexOf(objUnit.version) === -1)
		return callbacks.ifUnitError("wrong version");
	if (objUnit.alt !== constants.alt)
		return callbacks.ifUnitError("wrong alt");
```

**File:** signed_message.js (L33-41)
```javascript
	var objAuthor = {
		address: from_address,
		authentifiers: {}
	};
	var objUnit = {
		version: constants.version,
		signed_message: message,
		authors: [objAuthor]
	};
```

**File:** signed_message.js (L132-137)
```javascript
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
```

**File:** signed_message.js (L244-252)
```javascript
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
