## Analog Found

### Title
Unauthenticated Unit-Triggered Denial of Service via Unvalidated `earned_headers_commission_recipients` Array Elements - (File: validation.js)

### Summary
`validateHeadersCommissionRecipients()` iterates over the elements of the optional, attacker-controlled `earned_headers_commission_recipients` array without first checking that each element is a well-formed object, causing a synchronous, uncaught `TypeError` when an unprivileged unit poster supplies a non-object element (e.g. `null`). This mirrors the PocketMine-MP bug class: an unvalidated field is dereferenced during mandatory processing of unauthenticated/untrusted input, leading to a crash.

### Finding Description
`validateHeadersCommissionRecipients` only validates the array-level shape and each recipient's `earned_headers_commission_share`/`address`, but never confirms `recipient` itself is a non-empty object before dereferencing it: [1](#0-0) 

Specifically:
```
for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
    var recipient = objUnit.earned_headers_commission_recipients[i];
    if (!isPositiveInteger(recipient.earned_headers_commission_share))
```
If `recipient` is `null` (or any primitive), `recipient.earned_headers_commission_share` throws `TypeError: Cannot read properties of null`. The array itself only needs to pass `isNonemptyArray`, which does not check element types, so `earned_headers_commission_recipients: [null]` satisfies all prior checks: [2](#0-1) 

This function is called directly and synchronously from the main unit validation pipeline in `validate()`, which is the code path exercised for **every posted unit**, including from unauthenticated/unprivileged peers submitting new units: [3](#0-2) 

Because the field-name whitelist check earlier in `validate()` only verifies that `earned_headers_commission_recipients` is an allowed key — not that its contents are well-formed — a unit author fully controls the array contents: [4](#0-3) 

The throw occurs synchronously inside an `async.series` step nested inside `mutex.lock(...)` inside `validate()`. Since this is a plain `throw` inside a deeply nested callback (not routed through the `callback`/`cb` error-handling convention used everywhere else in this function), it escapes the `async.series` final error handler and propagates as an uncaught exception rather than an `ifUnitError`/`ifJointError` callback.

### Impact Explanation
Any full node or hub that receives and validates a maliciously crafted unit containing `earned_headers_commission_recipients: [null]` (or any array with a non-object element) will throw an uncaught `TypeError` mid-validation, while holding the `mutex.lock` on the author addresses and an open DB transaction. This is a crash/DoS vector triggered purely by posting a single malformed unit — no special privileges, hub/peer trust, or network position required — directly matching the "unauthenticated login field crash" class from the CVE report, adapted to "unauthenticated unit poster crashes unit validation."

### Likelihood Explanation
Multi-author units are common and legitimate uses of `earned_headers_commission_recipients` are expected, meaning validation of this field is on a hot, frequently-exercised path. Constructing the malicious payload requires no cryptographic material beyond what any unit poster already needs (valid authors/signatures for a normal multi-author unit) — only the recipients array itself needs to be malformed, since `hasFieldsExcept` does not validate element types.

### Recommendation
In `validateHeadersCommissionRecipients` (validation.js), add an explicit `isNonemptyObject(recipient)` (or equivalent) check for each array element before accessing its properties, returning `cb("recipient must be a non-empty object")` on failure, consistent with how other array-of-object fields (e.g. `objUnit.messages`, `payload.outputs`) are validated elsewhere in `validation.js`.

### Proof of Concept
Submit/post a unit joint with 2+ authors and:
```json
"earned_headers_commission_recipients": [ null ]
```
When `validate()` reaches `validateHeadersCommissionRecipients`, it dereferences `null.earned_headers_commission_share`, throwing an uncaught `TypeError` that crashes the validating node process before any `ifUnitError` callback can be invoked.

**Note:** I could not fully verify within the available search budget whether a global `process.on('uncaughtException')` handler in `network.js` (confirmed to exist via [5](#0-4) -level grep match, content not inspected) intercepts and gracefully recovers from this specific throw, or whether it still results in process termination/hung mutex state. This should be verified by a Devin agent with full file access before treating severity as definitive.

### Citations

**File:** validation.js (L190-191)
```javascript
		if (hasFieldsExcept(objUnit, ["unit", "version", "alt", "timestamp", "authors", "messages", "witness_list_unit", "witnesses", "earned_headers_commission_recipients", "last_ball", "last_ball_unit", "parent_units", "headers_commission", "payload_commission", "oversize_fee", "tps_fee", "burn_fee", "max_aa_responses"]))
			return callbacks.ifUnitError("unknown fields in unit");
```

**File:** validation.js (L385-389)
```javascript
				function(cb){
					profiler.stop('validation-checkDuplicate');
					profiler.start();
					objUnit.content_hash ? cb() : validateHeadersCommissionRecipients(objUnit, cb);
				},
```

**File:** validation.js (L1101-1126)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknown fields in recipient");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
	cb();
}
```

**File:** network.js (L1-1)
```javascript
/*jslint node: true */
```
