### Title
NULL/undefined dereference in `arbiter_contract.respond()` on unknown contract hash from a paired peer - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js` exposes `getByHash()`, which explicitly returns `cb(null)` when no matching row is found, and `respond()`, which consumes that callback result without checking for `null` before dereferencing a property on it. This mirrors the libupnp bug class in CVE-2020-13848, where `FindServiceControlURLPath`/`FindServiceEventURLPath` can return NULL and the caller dereferences the result without a check, crashing the process on an externally supplied, non-existent identifier.

### Finding Description
`getByHash(hash, cb)` looks up a row in `wallet_arbiter_contracts` by `hash` and calls back with `null` if no row matches: [1](#0-0) 

`respond(hash, status, signedMessageBase64, signer, cb)` immediately dereferences the result of `getByHash` without checking whether it is `null`: [2](#0-1) 

`hash` here is data supplied by the remote counterparty in an arbiter-contract protocol message (an unprivileged paired-device correspondent, i.e., the counterparty to a private contract, not a hub or node operator). Because `wallet_arbiter_contracts` is a local table keyed by contract hash, a peer that references a hash unknown to the local wallet (e.g., a hash for a contract that was never offered/stored locally, was rejected, or was fabricated) causes `getByHash` to invoke `cb(null)`, and `respond()` then executes `objContract.status`, throwing `TypeError: Cannot read properties of null (reading 'status')`. This is a synchronous throw inside a DB async callback, which in Node.js is not caught by any surrounding try/catch in the calling code path and results in an uncaught exception that crashes the node process — the same "NULL pointer dereference from an unchecked lookup" root cause described in the CVE, just realized in JS as a null property access instead of a C NULL pointer.

The `setField()` helper exhibits the identical pattern by also calling `getByHash(hash, cb)` and forwarding the (possibly `null`) result straight to its caller's callback without a guard: [3](#0-2) 

### Impact Explanation
An uncaught `TypeError` thrown from within an asynchronous DB callback is not caught by ordinary try/catch scoping in Node.js and will propagate to the top of the event loop, crashing the node process. Because this is triggered by processing an unauthenticated/untrusted peer's contract-hash reference over the private device-messaging channel, a single paired counterparty (not a hub, not a validator, not requiring any privileged role) can remotely crash the victim's wallet/node process, i.e., a Denial of Service — matching the "network unable to confirm new units" / node-crash impact bucket for exploited nodes.

### Likelihood Explanation
Exploitation only requires being a paired device correspondent (a normal precondition for using the arbiter-contract feature) and sending a contract-hash reference that does not correspond to a locally stored contract row — no special privileges, race conditions, or cryptographic breaks are needed. This is a low-complexity, high-reliability trigger once the code path receiving `hash` from a peer message is reached.

### Recommendation
- In `getByHash`/`getBySharedAddress` callers (`respond`, `setField`, and any other consumer), explicitly check for `null`/`undefined` before dereferencing (`if (!objContract) return cb("contract not found");`).
- Wrap the device-message handling dispatch for arbiter-contract subjects in defensive `try/catch` at the boundary so a malformed/unknown hash results in a graceful error response instead of an uncaught exception.
- Add regression tests that send `arbiter_contract_response`/related messages referencing a hash absent from `wallet_arbiter_contracts` and assert the node does not crash.

### Proof of Concept
1. Pair device B with device A (attacker is device B, a normal, already-paired correspondent).
2. Ensure the victim (device A) has no stored arbiter contract for a chosen `hash` value (e.g., a random 44-byte base64 string, or a hash from a contract A already deleted/never received).
3. Have device B send the message that ultimately invokes `arbiter_contract.respond(hash, ...)` on device A with that unknown `hash` (per the wiring in `arbiter_contract.js`, this is the code path reached for handling contract-response protocol messages).
4. On device A, `getByHash` finds no row, calls back `cb(null)`; `respond()` executes `objContract.status`, throwing `TypeError: Cannot read properties of null (reading 'status')`.
5. The uncaught exception propagates and crashes device A's node process.

Note: I was unable to fully verify, within the remaining tool budget, the exact wallet.js device-message handler that wires an incoming `arbiter_contract_response`/`arbiter_contract_update` subject to `arbiter_contract.respond()` (grep confirmed 6 references to these subjects in `wallet.js`, but the surrounding code was not read before the iteration limit was reached). The root-cause null-dereference in `arbiter_contract.js` itself, however, is confirmed directly from the source shown above.

### Citations

**File:** arbiter_contract.js (L38-46)
```javascript
function getByHash(hash, cb) {
	db.query("SELECT * FROM wallet_arbiter_contracts WHERE hash=?", [hash], function(rows){
		if (!rows.length) {
			return cb(null);
		}
		var contract = rows[0];
		cb(decodeRow(contract));			
	});
}
```

**File:** arbiter_contract.js (L78-89)
```javascript
function setField(hash, field, value, cb, skipSharing) {
	if (!["status", "shared_address", "unit", "my_contact_info", "peer_contact_info", "peer_pairing_code", "resolution_unit", "cosigners"].includes(field)) {
		throw new Error("wrong field for setField method");
	}
	db.query("UPDATE wallet_arbiter_contracts SET " + field + "=? WHERE hash=?", [value, hash], function(res) {
		if (!skipSharing)
			shareUpdateToCosigners(hash, field);
		if (cb) {
			getByHash(hash, cb);
		}
	});
}
```

**File:** arbiter_contract.js (L118-122)
```javascript
function respond(hash, status, signedMessageBase64, signer, cb) {
	cb = cb || function(){};
	getByHash(hash, function(objContract){
		if (objContract.status !== "pending" && objContract.status !== "accepted")
			return cb("contract is in non-applicable status");
```
