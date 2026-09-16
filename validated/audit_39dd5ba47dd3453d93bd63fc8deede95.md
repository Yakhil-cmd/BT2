### Title
Unbounded `arbiter_contract_update` listener growth in payment-received handler enables remote memory-exhaustion DoS - ([File: arbiter_contract.js])

### Summary
The `new_my_transactions` handler in `arbiter_contract.js` that checks for arbiter-contract payments registers a brand-new, non-self-removing `eventBus.on('arbiter_contract_update', retryPaymentCheck)` listener every single time it observes a qualifying payment while the contract is in `"accepted"` status, without ever de-duplicating or capping these registrations. This mirrors the CVE-2026-77384 bug class: a repeatable, attacker-controlled "valid request" (there, a RESERVE refresh; here, a payment received while status stays `accepted`) causes an event listener to be added on every occurrence but is only removed under a narrow condition, leading to unbounded listener/closure accumulation.

### Finding Description
In `arbiter_contract.js`, the listener block: [1](#0-0) 

registers on `new_my_transactions`, and inside it, whenever it finds an eligible payment to `wallet_arbiter_contracts.shared_address` while `contract.status === 'accepted'`, it does:
```
eventBus.on('arbiter_contract_update', function retryPaymentCheck(objContract, field, value){
	if (objContract.hash === contract.hash && field === 'unit') {
		newtxs(arrNewUnits);
		eventBus.removeListener('arbiter_contract_update', retryPaymentCheck);
	}
});
```
This uses `eventBus.on` (a persistent listener), not `eventBus.once`, and the removal only happens later, inside the listener body itself, when a specific `field === 'unit'` event for the same contract hash eventually fires. Nothing prevents the same `new_my_transactions` handler from re-entering this branch again before that condition ever fires — for example if the counterparty (or anyone able to cause payments to the shared address, since the contract is a shared/multisig address publicly known once created) sends multiple separate qualifying transactions to the same shared address while the contract remains in `"accepted"` status. Each new incoming transaction that satisfies the `HAVING SUM(outputs.amount) >= wallet_arbiter_contracts.amount` condition and finds `status === 'accepted'` registers one more anonymous `retryPaymentCheck` closure on the shared, long-lived `eventBus`, and none of the previously registered ones are removed (they all wait for the same future `field === 'unit'` event, which may never come, or may come only once, leaving the others dangling forever).

Since `eventBus` here is the same shared, long-lived Node `EventEmitter` used throughout the wallet process (also used by `network.js`, `wallet.js`, `device.js`, etc.), an unbounded number of listeners on the `arbiter_contract_update` event accumulate in the process memory, each holding closures over `contract`, `arrNewUnits`, and other captured objects. This is directly analogous to the reported libp2p bug where the reservation refresh path "reuses the same retimeableSignal but unconditionally registers another abort listener on every refresh," letting a peer "repeatedly send valid ... requests ... causing unbounded listener and closure growth."

### Impact Explanation
This is reachable by an unprivileged private-payment counterparty (the arbiter-contract peer or, in principle, anyone who learns the shared address and posts payment units to it, since being a "payment counterparty" of a shared address only requires knowing the address and posting a valid payment unit — no special permission is required to send funds to any address). Repeated qualifying deposits to the same shared address while the contract sits in `accepted` status cause continuous listener/closure growth on the process-wide `eventBus`, degrading and eventually crashing (via memory exhaustion / EventEmitter warnings turning into unresponsiveness) the victim's full node/wallet process — a legitimate node-availability impact ("a network unable to confirm new units" from that node's perspective, or at minimum denial of service to that wallet instance), consistent with the CVSS 7.5 (Availability-only) profile of the source CVE.

### Likelihood Explanation
The trigger conditions are attacker-reachable with ordinary wallet operations: an arbiter contract must exist and be in `accepted` state (a normal step in the arbiter-contract flow, reachable by any peer who negotiates such a contract), and the attacker (or even the shared address counterparty resending multiple small payments totaling more than the required amount, or paying twice) can cause `new_my_transactions` to fire repeatedly with amounts satisfying the `SUM(...) >= amount` condition. No special privileges, hub/relay control, or protocol violation are needed — only normal unit posting to a known address, which matches the "unprivileged unit poster" reachability requirement.

### Recommendation
- Use `eventBus.once` instead of `eventBus.on` for the `retryPaymentCheck` registration, or track and remove any previously registered listener for the same `contract.hash` before adding a new one (e.g., keep a map of `hash -> listener` and call `eventBus.removeListener` on any existing entry first).
- Alternatively, guard against re-registration by tracking an in-memory flag per `contract.hash` (`assocPendingRetryListeners[contract.hash]`) so at most one listener is ever outstanding per contract.
- Add an explicit cap/timeout so a stale `retryPaymentCheck` listener is removed after some bounded time even if the awaited `field === 'unit'` event never arrives.

### Proof of Concept
1. Attacker (peer B) and victim (peer A) set up an arbiter contract via the normal flow so that `wallet_arbiter_contracts` has a row with `status = 'accepted'`, a `shared_address`, and a required `amount`.
2. Peer B repeatedly posts new payment units to the shared address (e.g., splitting payments so each individually or cumulatively satisfies `SUM(outputs.amount) >= wallet_arbiter_contracts.amount`), or simply resends duplicate/overpayment transactions, without ever triggering the specific `field === 'unit'` event the listener is waiting for.
3. Each time `new_my_transactions` fires and the row query in [2](#0-1)  matches with `contract.status === 'accepted'`, a brand-new anonymous `retryPaymentCheck` listener is added to `eventBus` via `eventBus.on('arbiter_contract_update', ...)` and never removed.
4. Repeating step 2 indefinitely causes the number of registered listeners on `arbiter_contract_update` to grow without bound, consuming increasing memory and eventually degrading or crashing peer A's node process — the same "unbounded listener and closure growth" class of resource-exhaustion DoS described in CVE-2026-77384.

### Citations

**File:** arbiter_contract.js (L826-857)
```javascript
// contract payment received
eventBus.on("new_my_transactions", function newtxs(arrNewUnits) {
	db.query("SELECT hash, outputs.unit FROM wallet_arbiter_contracts\n\
		JOIN outputs ON outputs.address=wallet_arbiter_contracts.shared_address\n\
		CROSS JOIN units ON units.unit=outputs.unit\n\
		WHERE outputs.unit IN (" + arrNewUnits.map(db.escape).join(', ') + ") AND outputs.asset IS wallet_arbiter_contracts.asset AND (wallet_arbiter_contracts.status='signed' OR wallet_arbiter_contracts.status='accepted') AND units.sequence='good'\n\
		GROUP BY outputs.address\n\
		HAVING SUM(outputs.amount) >= wallet_arbiter_contracts.amount", function(rows) {
			rows.forEach(function(row) {
				getByHash(row.hash, function(contract){
					if (contract.status === 'accepted') { // we received payment already but did not yet receive signature unit message, wait for unit to be received
						eventBus.on('arbiter_contract_update', function retryPaymentCheck(objContract, field, value){
							if (objContract.hash === contract.hash && field === 'unit') {
								newtxs(arrNewUnits);
								eventBus.removeListener('arbiter_contract_update', retryPaymentCheck);
							}
						});
						return;
					}
					setField(contract.hash, "status", "paid", function(objContract) {
						eventBus.emit("arbiter_contract_update", objContract, "status", "paid", row.unit);
						// listen for peer announce to withdraw funds
						storage.readAssetInfo(db, contract.asset, function(assetInfo) {
							if (assetInfo && assetInfo.is_private)
								db.query("INSERT "+db.getIgnore()+" INTO my_watched_addresses (address) VALUES (?)", [objContract.peer_address]);

						});
					});
				});
			});
	});
});
```
