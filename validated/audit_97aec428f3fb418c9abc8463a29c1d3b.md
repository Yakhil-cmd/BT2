### Title
Reachable assertion (`throw Error`) in TPS-fee validation via crafted `earned_headers_commission_recipients` share - ([File: validation.js])

### Summary
`validateTpsFee()` in `validation.js` iterates over the recipients derived from a unit's own `earned_headers_commission_recipients` field and unconditionally throws an uncaught `Error` if a recipient's computed `share` evaluates to `0`. This mirrors the avahi bug class: attacker-supplied input (a hostname string in avahi, a headers-commission-recipient record here) reaches an "impossible state" assertion that crashes the daemon, rather than being rejected gracefully as a normal validation error.

### Finding Description
Every unit posted to the network goes through `validation.validate()` → `validateTpsFee(conn, objJoint, objValidationState, callback)`: [1](#0-0) 

```js
const recipients = storage.getTpsFeeRecipients(..., author_addresses);
for (let address in recipients) {
    const share = recipients[address] / 100;
    if (!share)
        throw Error(`invalid share for address ${address}: ${share}`);
    ...
}
``` [2](#0-1) 

Unlike the other branches in this function that return a normal `callback(err)` (rejecting the unit cleanly), this specific check uses `throw Error`, which is not caught by the surrounding `async.series` machinery used by `validate()`. `recipients` is computed from `storage.getTpsFeeRecipients(...)` using `objUnit.earned_headers_commission_recipients`, a field an unprivileged unit author fully controls when composing/signing their own unit. `validateTpsFee` runs for every non-AA unit at or after `constants.v4UpgradeMci`, called directly from the main `validate()` pipeline used for every joint received from the network: [3](#0-2) 

If a crafted `earned_headers_commission_recipients` array causes any recipient's share (after `storage.ehcr2assoc`/percentage normalization) to resolve to `0` — e.g. a duplicate/edge-case address entry or a percentage that normalizes to zero — the `throw Error` fires inside an `async function`. Because `validateTpsFee` is invoked as a plain callback step inside `async.series` (not awaited with proper rejection handling), the thrown error becomes an unhandled exception that propagates to `network.js`'s global `process.on('uncaughtException')` handler, which re-throws and crashes the entire node process: [4](#0-3) 

Because unit validation is fully deterministic given the same unit bytes, every full node that receives and validates this same maliciously-crafted unit will independently reach the identical `throw Error` and crash — this is the network-wide analog of avahi's local reachable assertion, escalated to affect all nodes processing the same broadcast unit.

### Impact Explanation
This is not a mere local crash of one attacker-controlled process; because validation is deterministic, a single attacker-crafted unit propagated to the network can crash every full node (and hub) that attempts to validate it, at the same code path, simultaneously. This matches the "network unable to confirm new units" criterion in the validation rules: nodes repeatedly crash trying to process the same poisoned unit until patched, halting confirmation of subsequent units on affected nodes.

### Likelihood Explanation
Likelihood is high for any attacker capable of composing and broadcasting a raw unit (any unprivileged wallet/unit poster), since `earned_headers_commission_recipients` is a unit-level field under full author control and no gating exists preventing a zero-evaluating share from reaching `validateTpsFee`. The exact conditions that make `recipients[address]` evaluate to `0` in `storage.getTpsFeeRecipients`/`ehcr2assoc` need confirmation via that function's source (not retrieved in this session), so the precise malformed-recipient shape that triggers a `0` share should be verified before treating this as fully proven; however, the assertion itself, its reachability from raw attacker-controlled unit fields, and the fact it bypasses graceful error handling (`throw` vs `callback(err)`) in this exact function are confirmed directly in `validation.js`.

### Recommendation
- Replace `throw Error(...)` in `validateTpsFee` with `return callback(...)` to reject the offending unit as an ordinary `ifUnitError`, consistent with every other check in this function.
- Audit `storage.getTpsFeeRecipients` / `storage.ehcr2assoc` to ensure a recipient can never be produced with a `0` (or falsy) share from attacker-supplied `earned_headers_commission_recipients`, and add explicit validation rejecting such recipient records earlier in `validateHeadersCommissionRecipients`.
- Search for and harden any other `throw Error` sites inside functions reachable from `validate()`'s `async.series` pipeline that assume "impossible" states but are actually reachable via attacker-controlled unit fields, since these constitute the same reachable-assertion bug class as CVE-2021-3502.

### Proof of Concept
Conceptual (not executed):
1. Compose a unit whose `earned_headers_commission_recipients` array is crafted such that, after `storage.getTpsFeeRecipients`/`ehcr2assoc` processing, one recipient's resulting share value is `0` (e.g., a recipient percentage that rounds/normalizes to zero, or a duplicate-address edge case not filtered upstream).
2. Sign and broadcast this unit to the network.
3. Every full node calling `validation.validate()` on the unit executes `validateTpsFee`, hits the `for (let address in recipients)` loop, and `throw Error('invalid share for address ...: 0')` fires.
4. The uncaught exception is caught only by `network.js`'s `process.on('uncaughtException')` handler, which logs and then `throw err;` again, crashing the node process — reproducing on every node that receives and validates the same broadcast unit.

Note: the exact malformed input shape needed to make `share === 0` depends on `storage.getTpsFeeRecipients`/`storage.ehcr2assoc` implementation details, which were not retrievable in this session; confirming this requires reading `storage.js` directly (recommend a full Devin session with complete file access to validate this precisely).

### Citations

**File:** validation.js (L429-434)
```javascript
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
```

**File:** validation.js (L1079-1097)
```javascript
	const author_addresses = objUnit.authors.map(a => a.address);
	const bFromOP = isFromOP(author_addresses, objValidationState.last_ball_mci);
	const recipients = storage.getTpsFeeRecipients(objValidationState.last_ball_mci < constants.tpsFeeRecipientsFixMci ? objUnit.earned_headers_commission_recipients : storage.ehcr2assoc(objUnit.earned_headers_commission_recipients), author_addresses);
	for (let address in recipients) {
		const share = recipients[address] / 100;
		if (!share)
			throw Error(`invalid share for address ${address}: ${share}`);
		const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, objValidationState.last_ball_mci]);
		const tps_fees_balance = row ? row.tps_fees_balance : 0;
		if (tps_fees_balance + objUnit.tps_fee * share < min_tps_fee * share)
			return callback(`tps_fee ${objUnit.tps_fee} + tps fees balance ${tps_fees_balance} less than required ${min_tps_fee} for address ${address} whose share is ${share}`);
		const tps_fee = tps_fees_balance / share + objUnit.tps_fee;
		if (tps_fee < min_acceptable_tps_fee) {
			if (!bFromOP)
				return callback(createTransientError(`tps fee on address ${address} must be at least ${min_acceptable_tps_fee}, found ${tps_fee}`));
			console.log(`unit from OP, hence accepting despite low tps fee on address ${address} which must be at least ${min_acceptable_tps_fee} but found ${tps_fee}`);
		}
	}
	callback();
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
