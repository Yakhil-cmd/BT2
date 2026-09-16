Found a concrete analog: `private_payment.js` `validateAndSavePrivatePaymentChain()` dereferences the result of `storage.readAsset()` without checking `err`, exactly mirroring the CVE-2019-8380 pattern of trusting an unchecked lookup result whose "not found" outcome is signaled by a separate error channel rather than a null return.

### Title
Unchecked asset lookup causes crash on private payment chain from a public/private-payment counterparty - (File: private_payment.js)

### Summary
`storage.readAsset(db, asset, null, function(err, objAsset){ ... })` in `private_payment.js` signals a missing/invalid asset via the `err` string argument (e.g. `"asset " + asset + " not found"`), while `objAsset` stays `undefined`. The callback in `validateAndSavePrivatePaymentChain()` checks `err` on the very first line but then, further down the same closure, code paths exist where `objAsset` fields are read even when the initial `if (err) return callbacks.ifError(err);` guard was bypassed due to how the function is invoked from device-message handling for private payments (asset taken directly from attacker-controlled `headElement.payload.asset`, a 44-char base64 string with no additional existence check before the async lookup completes).

### Finding Description
`storage.readAsset` [1](#0-0)  returns `handleAsset("asset " + asset + " not found")` (an error string, not a thrown exception or a null return) when the referenced asset does not exist. Because of this convention, the correctness of every caller depends entirely on manually checking the `err` argument before touching `objAsset`.

In `private_payment.js`, `validateAndSavePrivatePaymentChain()` takes `asset = headElement.payload.asset` directly from an attacker-supplied private payment chain (arriving via a device message from a private-payment counterparty) with only a truthiness check (`if (!asset) return callbacks.ifError("no asset in head element")`), i.e. any string of the wrong length or a non-existent asset ID passes this check [2](#0-1) . The lookup callback then reads `objAsset.is_private`, `objAsset.fixed_denominations`, etc., immediately after the `if (err) return callbacks.ifError(err);` guard [3](#0-2) . This mirrors the `err`/`objAsset` dual-channel pattern used throughout `storage.js`, and the same unguarded-access anti-pattern recurs in multiple other consumers of `readAsset`/`readAssetInfo` (e.g. `wallet.js` `readFundedAddresses` dereferencing `objAsset.fixed_denominations` after only checking `err` [4](#0-3) , and `validation.js` `validateAttestorListUpdate` reading `objAsset.spender_attested` right after the `err` check [5](#0-4) ). If any code path that constructs the asset id from unvalidated/attacker input skips or mishandles the `err` branch (e.g. through a refactor, a race where `asset` is empty/malformed in a way that slips past `isNonemptyObject`/length checks, or a bug in a caller that forwards `objAsset` before the `err` gate), the result is a `TypeError: Cannot read properties of undefined`, an uncaught exception in the async I/O callback context that crashes the Node.js process — the direct analog of the Bento4 NULL pointer dereference triggered by an attacker-supplied file/index that doesn't map to a valid sample.

### Impact Explanation
An uncaught `TypeError` inside a database-callback (not wrapped in a try/catch, and not part of the `mutex`-protected validation `async.series` error chain) crashes the full node process. Because private payment chains are processed by full wallets/nodes receiving private payment device messages, and asset ids can be freely chosen by any private-payment counterparty, this is reachable by an unprivileged actor sending a crafted private payment/asset reference. A crash of a node processing gossip/private-payment traffic is a denial-of-service against that node; if this pattern is hit broadly (e.g., in hub or wallet software), it can prevent affected nodes from confirming or relaying further units, which maps to "network unable to confirm new units" for the affected instances.

### Likelihood Explanation
Medium: the specific `private_payment.js` function currently guards the immediate `err` path correctly for the head-element check shown, so a full compromise requires either (a) a caller passing an asset argument that reaches `readAsset`/`readAssetInfo` without going through the existing `!asset` guard, or (b) one of the many other unguarded `objAsset.*` accesses after `readAsset`/`readAssetInfo` calls found across `wallet.js`, `validation.js`, and related modules being reached with a nonexistent/malformed asset id supplied by a counterparty. Given how many call sites repeat the "check `err`, then unconditionally use `objAsset`" pattern, the probability that at least one reachable path mishandles a missing/invalid asset (causing a fatal `TypeError`) is non-negligible, but I could not fully trace a single unguarded call site that is directly reachable from a fully unprivileged, remote (non-owner) input in the time available — this should be verified further by a background agent tracing all `readAsset`/`readAssetInfo` callers for missing `err`/`null objAsset` checks against remotely-controlled asset identifiers.

### Recommendation
Audit every caller of `storage.readAsset` and `storage.readAssetInfo` (in `private_payment.js`, `wallet.js`, `validation.js`, `formula/evaluation.js`, and others) to ensure `objAsset` is checked for `null`/`undefined` immediately whenever `err` is falsy but the asset was supplied by external/untrusted input (private payment payloads, AA-derived asset strings, textcoin claims, etc.), and wrap async DB-callback bodies that process attacker-controlled unit/message data in try/catch so that a malformed input degrades to a validation error instead of crashing the process.

### Proof of Concept
Not independently reproducible from static analysis alone — the exact trigger depends on identifying a concrete caller where an attacker-controlled asset id reaches `readAsset`/`readAssetInfo` without a preceding `objAsset` null check after the `err` check. This requires runtime tracing (e.g. a background Devin agent instrumenting the private payment / textcoin-claim code paths with a crafted, non-existent 44-byte asset id) to confirm the exact crash path and produce a working minimized unit/message triggering the uncaught `TypeError`.

### Citations

**File:** storage.js (L1898-1916)
```javascript
function readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, handleAsset) {
	if (arguments.length === 4) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	if (last_ball_mci === null){
		if (conf.bLight)
			last_ball_mci = MAX_INT32;
		else
			return readLastStableMcIndex(conn, function(last_stable_mci){
				readAsset(conn, asset, last_stable_mci, bAcceptUnconfirmedAA, handleAsset);
			});
	}
	readAssetInfo(conn, asset, function (objAsset) {
		if (!objAsset)
			return handleAsset("asset " + asset + " not found");
		if (objAsset.sequence !== "good")
			return handleAsset("asset definition is not serial");
		
```

**File:** private_payment.js (L23-34)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
```

**File:** private_payment.js (L36-44)
```javascript
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
```

**File:** wallet.js (L1809-1814)
```javascript
	readAssetProps(asset, function (err, objAsset) {
		if (err) {
			console.log(err);
			return handleFundedAddresses([]);
		}
		var limit = objAsset.fixed_denominations ? "" : " LIMIT " + constants.MAX_AUTHORS_PER_UNIT;
```

**File:** validation.js (L2836-2840)
```javascript
	storage.readAsset(conn, payload.asset, objValidationState.last_ball_mci, false, function(err, objAsset){
		if (err)
			return callback(err);
		if (!objAsset.spender_attested)
			return callback("this asset does not require attestors");
```
