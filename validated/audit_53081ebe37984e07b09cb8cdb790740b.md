### Title
Shared `my_watched_addresses` entries can be removed while still needed by another active arbiter role - (File: `arbiter_contract.js`)

### Summary
`wallet_general.removeWatchedAddress()` performs an unconditional `DELETE FROM my_watched_addresses WHERE address=?` [1](#0-0)  for a single address. `arbiter_contract.js` calls this function from two independent event handlers, each of which only checks whether *that handler's specific role* (arbiter vs. peer) still needs the address watched, without checking whether the same address is still required to be watched for the *other* role. This mirrors the Knox `epochsByBuyer[]` bug class: a shared tracking structure keyed by address is deleted based on the completion of one logical "order"/contract while ignoring that other logical entries still reference the same key.

### Finding Description
When a user opens a dispute, the arbiter's address is inserted into `my_watched_addresses` so the wallet can observe the arbiter's resolution unit: [2](#0-1) 

Later, once a unit authored by that arbiter address stabilizes, the wallet checks **only contracts where this address is the `arbiter_address`** (`getAllByArbiterAddress`) and, if none remain `in_dispute`, calls `wallet_general.removeWatchedAddress(address)`: [3](#0-2) 

Separately, for private-asset contracts, once a `peer_address`'s "paid" contracts all complete, the wallet checks **only contracts where this address is the `peer_address`** (`getAllByPeerAddress`) and calls the same `removeWatchedAddress`: [4](#0-3) 

Because `wallet_arbiter_contracts.arbiter_address`, `.peer_address`, and `.my_address` are all drawn from the same address space (any Obyte address can simultaneously be an arbiter for one contract and a counterparty/peer for another), the same underlying address can be the reason a wallet must remain watching it for *two unrelated* contracts at once. Each of the two cleanup handlers reasons only about its own role (arbiter-role count, or peer-role count) and neither cross-checks the other role before issuing the blind `DELETE`. If:
1. Address `X` is watched both as an `arbiter_address` for contract A (dispute in progress) and as a `peer_address` for contract B (private-asset payment pending release), and
2. Contract B's "paid" count reaches zero (e.g., completed) while contract A's dispute is still open,

then the peer-address handler's `removeWatchedAddress(X)` deletes the row from `my_watched_addresses` unconditionally, silencing the wallet's ability to detect the incoming arbiter resolution unit for contract A, even though contract A still needs `X` watched.

Conversely, the arbiter-response handler's cleanup can equally wipe the watch that was needed for an active peer-address monitoring case if the roles are reversed. There is no reference counting or union check across the different insertion sites into `my_watched_addresses` for the same address — exactly the "the record will be inaccurate ... impossible to track the other [order/contract] put by the user" pattern from the Knox report, applied to a watched-address set instead of an epoch array.

### Impact Explanation
If the shared watch entry is prematurely deleted, the affected wallet will stop being notified (`new_my_transactions` / `my_transactions_became_stable` won't fire for units from/to that address per `notifyWatchers` / `notifyLocalWatchedAddressesAboutStableJoints`, which both key off `my_watched_addresses`) about units concerning the address that is still legitimately relevant to another pending arbiter contract. This can cause the wallet to miss the arbiter's dispute-resolution unit or a counterparty's private-payment release notification, leaving the affected party unaware that a dispute resolved in their favor or that a fund release condition occurred — a fund-loss/fund-freezing risk for money already committed to an arbiter/private-asset contract, since claiming/reacting to a contract may depend on the wallet catching that event.

### Likelihood Explanation
The trigger requires only that the same address, controlled by the victim's wallet, is reused as an `arbiter_address` in one arbiter contract and as a `peer_address`/`my_address` in another unrelated arbiter contract concurrently — a plausible and unprivileged scenario reachable purely by posting/accepting arbiter contracts and interacting via device messages/units, which any counterparty or arbiter can drive without special privilege.

### Recommendation
Do not remove a `my_watched_addresses` entry based on a single-role count. Instead, when deciding to unwatch an address, query across all roles (`arbiter_address`, `peer_address`, `my_address`) and all statuses that still require watching that address before issuing `wallet_general.removeWatchedAddress()`, or switch to a reference-counted/multi-reason watch table so that unwatching one contract's need does not clear watches still required by another contract.

### Proof of Concept
1. Device D creates arbiter contract A with counterparty P1, where D acts as arbiter for a different contract B is not needed—use instead: Device D is party to contract A where address `X` (belonging to D) is the `peer_address` used in a private-asset flow, and address `X` is *also* used as `arbiter_address` in unrelated contract C for which D previously opened a dispute (`openDispute` inserted `X` into `my_watched_addresses`, per `arbiter_contract.js:307-312`).
2. Contract A's private-asset payment completes; the "unit with peer funds release" handler runs `getAllByPeerAddress(X, ...)`, finds no remaining `"paid"` contracts for peer-role `X`, and calls `wallet_general.removeWatchedAddress(X)` (`arbiter_contract.js:967-979`), deleting `X` from `my_watched_addresses`.
3. Contract C's arbiter later posts the dispute-resolution unit authored by `X`. Since `X` no longer appears in `my_watched_addresses`, `notifyWatchers`/`notifyLocalWatchedAddressesAboutStableJoints` (`network.js`) do not flag the unit as relevant, so D's wallet never emits `new_my_transactions`/`my_transactions_became_stable` for it, and the "arbiter response" handling in `arbiter_contract.js:878-901`/`903-934` never fires for D — D's wallet silently misses the dispute resolution.

### Citations

**File:** wallet_general.js (L88-90)
```javascript
function removeWatchedAddress(address){
	db.query("DELETE FROM my_watched_addresses WHERE address=?", [address], function(){});
}
```

**File:** arbiter_contract.js (L307-312)
```javascript
							setField(hash, "status", "in_dispute", function(objContract) {
								shareUpdateToPeer(hash, "status");
								// listen for arbiter response
								db.query("INSERT "+db.getIgnore()+" INTO my_watched_addresses (address) VALUES (?)", [objContract.arbiter_address]);
								cb(null, resp, objContract);
							});
```

**File:** arbiter_contract.js (L903-934)
```javascript
// arbiter response stabilized
eventBus.on("my_transactions_became_stable", function(units) {
	db.query(
		"SELECT DISTINCT unit_authors.unit \n\
		FROM unit_authors \n\
		JOIN wallet_arbiter_contracts ON address=arbiter_address \n\
		CROSS JOIN units ON units.unit=unit_authors.unit \n\
		WHERE unit_authors.unit IN(" + units.map(db.escape).join(', ') + ") AND units.sequence='good'",
		function (rows) {
			units = rows.map(row => row.unit);
			units.forEach(function(unit) {
				storage.readUnit(unit, function(objUnit) {
					var address = objUnit.authors[0].address;
					getAllByArbiterAddress(address, function(contracts) {
						var count = 0;
						contracts.forEach(function(objContract) {
							if (objContract.status !== "dispute_resolved" && objContract.status !== "in_dispute") // we still can be in dispute in case of light wallet stayed offline
								return;
							var winner = parseWinnerFromUnit(objContract, objUnit);
							if (winner === objContract.my_address)
								eventBus.emit("arbiter_contract_update", objContract, "resolution_unit_stabilized", null, null, winner);
							if (objContract.status === "in_dispute")
								count++;
						});
						if (count === 0)
							wallet_general.removeWatchedAddress(address);
					});
				});
			});
		}
	);
});
```

**File:** arbiter_contract.js (L936-990)
```javascript
// unit with peer funds release for private assets became stable
eventBus.on("my_transactions_became_stable", function(units) {
	db.query(
		"SELECT DISTINCT unit_authors.unit \n\
		FROM unit_authors \n\
		JOIN wallet_arbiter_contracts ON (address=peer_address OR address=my_address) \n\
		JOIN assets ON asset=assets.unit \n\
		JOIN units ON units.unit=unit_authors.unit \n\
		WHERE unit_authors.unit IN(" + units.map(db.escape).join(', ') + ") AND is_private=1 AND units.sequence='good'",
		function (rows) {
			units = rows.map(row => row.unit);
			units.forEach(function (unit) {
				storage.readUnit(unit, function (objUnit) {
					objUnit.messages.forEach(function (m) {
						if (m.app !== "data_feed")
							return;
						for (let key in m.payload) {
							const contract_hash_matches = key.match(/CONTRACT_DONE_(.+)/);
							if (!contract_hash_matches)
								continue;
							const contract_hash = contract_hash_matches[1];
							getByHash(contract_hash, function (objContract) {
								if (!objContract)
									return;
								if (objContract.peer_address !== objUnit.authors[0].address)
									return;
								storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
									if (!assetInfo || !assetInfo.is_private)
										return;
									if (m.payload[key] != objContract.my_address)
										return;
									if (objContract.status === 'paid') {
										const status = objContract.me_is_payer ? 'cancelled' : 'completed';
										setField(contract_hash, 'status', status, function (objContract) {
											eventBus.emit("arbiter_contract_update", objContract, "status", status, unit, null, true);
											let count = 0;
											getAllByPeerAddress(objContract.peer_address, function (contracts) {
												contracts.forEach(function (objContract) {
													if (objContract.status === "paid")
														count++;
												});
												if (count == 0)
													wallet_general.removeWatchedAddress(objContract.peer_address);
											});
										});
									}
								});
							});
						}
					});
				});
			});
		}
	);
});
```
