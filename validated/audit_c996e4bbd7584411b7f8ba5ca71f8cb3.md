### Title
Hardcoded `maxVersion` bound in `is_valid_signed_package` will reject valid signed packages after a future protocol/version upgrade - (File: formula/evaluation.js)

### Summary
The oscript function `is_valid_signed_package()`, reachable from any AA definition, bounds the `version` field of a `signed_package` object against a hardcoded literal `4` instead of deriving it from an upgradable, mci-gated constant. If the protocol later introduces a new unit version (e.g. `5.0`) via a new upgrade MCI — the standard mechanism ocore already uses everywhere else (`v4UpgradeMci`, `aa3UpgradeMci`, etc.) — this code path keeps rejecting otherwise valid, correctly-signed packages until the ocore source itself is patched and every full node redeployed, exactly mirroring the reported hardcoded-`chainID` pattern (works fine until a fork changes the environment, then requires a code fix/redeploy instead of adapting automatically).

### Finding Description
In `formula/evaluation.js`, the `is_valid_signed_package` opcode handler validates the optional `version` field of the passed-in signed package: [1](#0-0) 

```
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
```

The comment itself, `// depends on mci in the future updates`, acknowledges that this bound is meant to be MCI-dependent, exactly like every other protocol-version gate in the codebase (e.g. `constants.v4UpgradeMci` used throughout `composer.js` and `object_hash.js` to select the active unit `version`) [2](#0-1) . Instead, the bound is a bare numeric literal (`4`) that is not tied to `constants.fVersion4` [3](#0-2)  or to any upgrade MCI, so it cannot adapt automatically when the network's supported unit version advances past `4.0` in a future hard fork (the same way `constants.version`/`constants.supported_versions` are bumped for each network upgrade in `constants.js`) [4](#0-3) .

This function is directly reachable by any AA author: an AA's oscript definition can call `is_valid_signed_package(trigger.data.signed_package, address)` to validate a signed data package submitted by an unprivileged trigger sender (e.g., a price oracle signing off-chain data) [5](#0-4) .

### Impact Explanation
Because the version ceiling is hardcoded rather than tracking the live protocol version the same way `constants.version`/`supported_versions` do, any future hard fork that introduces a unit version greater than `4.0` will cause all `is_valid_signed_package()` calls that check `signedPackage.version` to return `false` for otherwise perfectly valid, correctly-signed packages using the new version — even though `signed_message.validateSignedMessage()` itself already correctly validates versions against the dynamic `constants.supported_versions` list [6](#0-5) . Any AA that gates fund release, oracle price acceptance, or other logic on `is_valid_signed_package()` succeeding would start unconditionally rejecting legitimate signed packages after the fork, effectively freezing AA functionality/funds that depend on this validation, until the ocore code is patched with a new literal and all full nodes are upgraded/redeployed — the direct analog of the reported "hardcoded chainID forces redeployment" issue.

### Likelihood Explanation
This triggers deterministically and automatically the moment a future version bump takes effect network-wide (a certainty over the protocol's lifetime, similar to how `v4UpgradeMci` was introduced for the last version bump); no attacker action is needed, only the passage of a scheduled/consensus upgrade. Because full nodes must all apply the same evaluation deterministically for consensus, this is not a "someday maybe" issue — it will directly and reproducibly happen for every AA relying on `is_valid_signed_package` with an explicit `version` field once the next hard fork ships a unit version above `4`.

### Recommendation
Replace the hardcoded literal with a reference to the live protocol constant/mci gate, e.g. `constants.fVersion4` extended to a properly maintained "current max supported version" constant that is bumped alongside `constants.version`/`constants.supported_versions` at each upgrade, or derive the ceiling from `constants.supported_versions` (e.g., `Math.max(...constants.supported_versions.map(parseFloat))`) so the check adapts automatically instead of requiring a source-code patch and redeployment at every future hard fork.

### Proof of Concept
1. Assume a future upgrade introduces unit version `"5.0"` and updates `constants.version`/`constants.supported_versions` accordingly (as was done historically for `v4UpgradeMci`) [2](#0-1) .
2. An off-chain signer produces a `signed_message` package with `version: "5.0"`, which passes `validateSignedMessage()`'s dynamic version check [6](#0-5) .
3. An AA trigger includes this signed package in `trigger.data.signed_package`, and the AA's oscript calls `is_valid_signed_package(trigger.data.signed_package, address)`.
4. In `formula/evaluation.js`, `fVersion = 5 > maxVersion (hardcoded 4)`, so the call returns `false` regardless of a valid signature, blocking the AA logic that depends on this check [7](#0-6) .

### Citations

**File:** formula/evaluation.js (L1674-1682)
```javascript
						if (signedPackage.version) {
							if (typeof signedPackage.version !== 'string')
								return cb(false);
							if (signedPackage.version === constants.versionWithoutTimestamp)
								return cb(false);
							const fVersion = parseFloat(signedPackage.version);
							const maxVersion = 4; // depends on mci in the future updates
							if (fVersion > maxVersion)
								return cb(false);
```

**File:** constants.js (L24-27)
```javascript
exports.version = exports.bTestnet ? '4.0t' : '4.0';
exports.alt = exports.bTestnet ? '2' : '1';

exports.supported_versions = exports.bTestnet ? ['1.0t', '2.0t', '3.0t', '4.0t'] : ['1.0', '2.0', '3.0', '4.0'];
```

**File:** constants.js (L31-31)
```javascript
exports.fVersion4 = 4;
```

**File:** constants.js (L99-99)
```javascript
exports.v4UpgradeMci = exports.bTestnet ? 3522600 : 10968000;
```

**File:** test/formula.test.js (L1748-1752)
```javascript
	evalFormulaWithVars({ conn: db, formula: "is_valid_signed_package(trigger.data.signed_package, '"+address+"')", trigger: trigger, objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU' }, (res, complexity) => {
		t.deepEqual(res, true);
		t.deepEqual(complexity, 2);
		t.end();
	})
```

**File:** signed_message.js (L136-137)
```javascript
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
```
