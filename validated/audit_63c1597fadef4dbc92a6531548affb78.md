### Title
Unbounded EventEmitter Listener Accumulation in Arbiter Contract Payment Retry Logic - ([File: arbiter_contract.js])

### Summary
The `new_my_transactions` handler in `arbiter_contract.js` that watches for arbiter-contract shared-address payments registers a brand-new, never-guaranteed-to-be-removed listener on the global `eventBus` for every incoming payment batch that arrives while the local contract is in the `accepted` state. A private-payment counterparty (the contract peer) who controls when/whether to send the follow-up "unit" signature message can force this code path to run repeatedly without ever triggering listener cleanup, causing unbounded memory growth in the node process — the same "memory consumption via repeated legitimate-looking action" bug class as CVE-2017-9373 (QEMU AHCI hot-unplug leak), just reached through the wallet/arbiter-contract message flow instead of device hot-plug.

### Finding Description
In the `new_my_transactions` listener: [1](#0-0) 

Whenever a payment arrives for a shared address tied to an arbiter contract whose status is `accepted`, and the total received meets the contract amount, the handler does:

```js
if (contract.status === 'accepted') { // we received payment already but did not yet receive signature unit message, wait for unit to be received
    eventBus.on('arbiter_contract_update', function retryPaymentCheck(objContract, field, value){
        if (objContract.hash === contract.hash && field === 'unit') {
            newtxs(arrNewUnits);
            eventBus.removeListener('arbiter_contract_update', retryPaymentCheck);
        }
    });
    return;
}
```

This closure captures `arrNewUnits` and is only ever removed when a later `arbiter_contract_update` event fires with `field === 'unit'` for this exact contract hash — i.e., only when the peer eventually sends the signed contract unit message (`device.js`/contract flow) that leads to `setField(hash, 'unit', ...)`. Nothing bounds how many times this branch can be entered, and nothing removes stale listeners if the peer never sends the `unit` update.

Because `new_my_transactions` fires on every batch of new incoming transactions to the wallet (not just once per contract), a peer who keeps sending additional small payments to the shared multi-sig address associated with the contract (which is trivial for the contract counterparty to do, since they are one of the co-signers/parties of that shared address) re-enters this branch on every such batch as long as the contract remains in `accepted` status and the peer simply withholds the `unit` message. Each re-entry adds one more `arbiter_contract_update` listener that is never cleaned up.

This is a genuine unbounded resource-leak (listener + closure + captured `arrNewUnits` array) directly triggerable by an unprivileged private-payment counterparty repeatedly performing an otherwise legitimate action (sending payments), analogous to how CVE-2017-9373 allowed an unprivileged guest to leak memory via repeated hot-unplug of a device.

### Impact Explanation
Unbounded `EventEmitter` listener accumulation leads to steadily growing heap usage (each listener closure retains `contract`, `arrNewUnits`, and their referenced data) that is never released. Over time this results in denial of service through memory exhaustion of the wallet node process, and Node's default `MaxListenersExceededWarning` mechanism does not prevent unbounded registration since listeners are added under distinct function references. A malicious or careless private-payment counterparty can force this indefinitely, without requiring any privileged network position, hub compromise, or protocol-level attack — matching the Medium severity profile of the CVE analog (local/paired actor causing memory-consumption DoS).

### Likelihood Explanation
The counterparty of an arbiter contract routinely controls sending additional payments to the jointly-controlled shared address and controls the timing of sending the "unit" signature message that would clear the leaked listener. Simply delaying or never sending that message while sending repeated small payments to the shared address is a low-effort action fully within the normal arbiter-contract negotiation flow, making this reachable without any special access.

### Recommendation
- Deduplicate/guard the `retryPaymentCheck` listener registration per contract hash (e.g., track outstanding listeners in a map keyed by `contract.hash` and skip adding a new one if one is already pending).
- Add a TTL/expiration or maximum retry count for these listeners, removing them after a bounded time or number of attempts regardless of whether the `unit` update ever arrives.
- Alternatively, replace the ad hoc `eventBus.on`/`removeListener` pattern with a one-shot `eventBus.once` combined with an explicit timeout-based removal to guarantee bounded listener lifetime.

### Proof of Concept
1. Two wallets establish an arbiter contract (`createAndSend` in `arbiter_contract.js`) with a shared multi-sig address, and the contract is moved into `accepted` status through the normal negotiation.
2. The peer (private-payment counterparty) sends the required payment amount to the shared address once — the `accepted`-status branch fires and registers listener #1.
3. Without ever sending the follow-up "unit" signature device message, the peer sends additional payments to the same shared address (any positive amount, in additional units) as often as they like; each new `new_my_transactions` batch containing an output to the shared address re-enters the `accepted` branch, registering another closure-bound `arbiter_contract_update` listener each time.
4. None of these listeners are ever removed, since removal requires `field === 'unit'`, which the peer withholds indefinitely, causing continuous growth of `eventBus`'s listener list and associated retained memory in the victim's node process.

### Citations

**File:** arbiter_contract.js (L826-856)
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
```
