### Title
Escrowed funds can be permanently frozen if the arbiter never resolves a dispute - (File: arbiter_contract.js)

### Summary
The arbiter-contract escrow mechanism in `arbiter_contract.js` locks payer/payee funds in a shared multi-authentifier address whose release conditions depend on the arbiter posting a `data_feed` naming the winner. Just like the PeriodicPrizeStrategy RNG example (where a stuck RNG request permanently blocks withdrawals because no code path exists to exit the "pending award" state), once a contract enters `in_dispute`, the only on-chain paths that release the shared address's funds without a genuinely cooperative counterparty are gated on the arbiter's data feed. If the arbiter (a single external, possibly offline/unresponsive party) never posts a resolution, and the disputing counterparties will not voluntarily concede the full amount to each other, the funds in the shared address are locked indefinitely with no timeout, exit function, or arbiter-replacement mechanism.

### Finding Description
`deriveSharedAddress()` builds the shared-address definition with five alternative unlocking branches: [1](#0-0) 

Two of these branches require BOTH parties' signatures (mutual cooperation), two require one party to unilaterally pay the *entire* disputed amount to the counterparty (for public assets) or require the counterparty to voluntarily post a `CONTRACT_DONE_<hash>` data feed releasing the funds (for private assets): [2](#0-1) 

The remaining two branches are gated purely on the arbiter posting a `data_feed` message `CONTRACT_<hash> = winner_address`, which is what `openDispute()` waits for after submitting a dispute to the arbiter/arbstore: [3](#0-2) 

`parseWinnerFromUnit()` and the `new_my_transactions` / `my_transactions_became_stable` listeners only progress the contract status (`dispute_resolved`) when a unit authored by `arbiter_address` contains this data feed; there is no timeout, fallback, or alternate resolution path: [4](#0-3) [5](#0-4) 

The `ttl` field on `wallet_arbiter_contracts` only bounds the pre-signature "pending" offer stage (checked in `wallet.js` when accepting the initial offer) and has no effect once the contract is `paid`/`in_dispute`, so it provides no escape from a stuck dispute: [6](#0-5) 

In a genuine dispute the two counterparties disagree by definition, so the "pay in full" unilateral branches and the mutual-signature branch will not be exercised voluntarily — exactly mirroring the RNG report's observation that `requireNotLocked()`/`setRngService()` block any progress until the pending external process (RNG request, here: arbiter resolution) completes, with no `exitAwardPhase()`-equivalent function to force an exit.

### Impact Explanation
If the arbiter's device/hub becomes permanently unreachable, is compromised, or simply refuses/forgets to respond (no SLA is enforced anywhere in this code), any escrowed amount already paid into the shared address (`pay()`/`new_my_transactions` handler moving status to `paid` then `in_dispute`) becomes unspendable by either honest party for as long as the counterparty refuses to concede. This is a concrete freezing of user funds (AA/wallet fund freezing category) reachable by any two ordinary paired-device wallet users who use the arbiter-contract feature — no privileged access is required, and the loss is triggered purely by the arbiter's failure to respond, a condition neither counterparty controls.

### Likelihood Explanation
Likelihood is moderate: it requires (1) an actual dispute to be opened and (2) the chosen arbiter to become unavailable or unresponsive. Arbiters are third-party services outside of ocore's control (comparable to the external RNG provider in the report), so unavailability, downtime, or malicious/negligent arbiters are a realistic and foreseeable failure mode explicitly acknowledged by the RNG report's bug class. Once triggered, the locked state is not self-healing — there is no retry, timeout, or governance path in the codebase to recover.

### Recommendation
Add a dispute-timeout / arbiter-fallback mechanism analogous to the suggested `exitAwardPhase()`:
- Allow the contract counterparties to trigger an automatic, non-cooperative resolution (e.g., default refund/split, or ability to name a substitute arbiter) once a configurable timeout elapses after `openDispute()` without a resolving data feed from the arbiter.
- Alternatively, embed a time-locked fallback branch directly in the shared-address `arrDefinition` produced by `deriveSharedAddress()` (e.g., allow either party to unilaterally reclaim their pre-dispute share after `timestamp > dispute_time + N`), so funds are never permanently unspendable regardless of arbiter behavior.

### Proof of Concept
1. Alice and Bob create an arbiter contract and fund the shared address via `createSharedAddressAndPostUnit()`/`pay()`, moving status to `paid`. [7](#0-6) 
2. Alice calls `openDispute()`, moving status to `in_dispute` and notifying the arbstore. [3](#0-2) 
3. The arbiter's hub/device goes permanently offline (or the arbiter simply never posts the `CONTRACT_<hash>` data feed).
4. Bob refuses to sign a mutual release and refuses to concede the full amount (since he disputes owing it), which is precisely why the dispute exists.
5. No unit satisfying any of the five branches in `arrDefinition` (`arbiter_contract.js:465-481`) can ever be produced: mutual signature is refused, unilateral "pay in full"/data-feed-release branches are refused, and the arbiter's data feed never arrives.
6. The funds in the shared address remain permanently unspendable — there is no function in `arbiter_contract.js` (`appeal()`, `complete()`, or otherwise) that can unlock them without one of the five original definition branches being satisfied.

### Citations

**File:** arbiter_contract.js (L262-318)
```javascript
function openDispute(hash, cb) {
	getByHash(hash, function(objContract){
		if (!["paid", "in_dispute"].includes(objContract.status))
			return cb("contract can't be disputed");
		device.requestFromHub("hub/get_arbstore_url", objContract.arbiter_address, function(err, url){
			if (err)
				return cb(err);
			arbiters.getInfo(objContract.arbiter_address, async function(err, objArbiter) {
				if (err)
					return cb(err);
				err = await fillArbstoreAddresses(objContract);
				if (err)
					return cb(err);
				device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
					var my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
					var data = {
						contract_hash: hash,
						unit: objContract.unit,
						my_address: objContract.my_address,
						peer_address: objContract.peer_address,
						me_is_payer: objContract.me_is_payer,
						my_pairing_code: objContract.my_pairing_code,
						peer_pairing_code: objContract.peer_pairing_code,
						encrypted_contract: device.createEncryptedPackage({
							title: objContract.title,
							text: objContract.text,
							creation_date: objContract.creation_date,
							plaintiff_party_name: objContract.my_party_name,
							respondent_party_name: objContract.peer_party_name,
							my_contact_info: objContract.my_contact_info,
							peer_contact_info: objContract.peer_contact_info,
						}, objArbiter.device_pub_key),
						my_contact_info: objContract.my_contact_info,
						peer_contact_info: objContract.peer_contact_info
					};
					db.query("SELECT 1 FROM assets WHERE unit IN(?) AND is_private=1 LIMIT 1", [objContract.asset], function(rows){
						if (rows.length > 0) {
							data.asset = objContract.asset;
							data.amount = objContract.amount;
						}
						var dataJSON = JSON.stringify(data);
						httpRequest(url, "/api/dispute/new", dataJSON, function(err, resp) {
							if (err)
								return cb(err);

							setField(hash, "status", "in_dispute", function(objContract) {
								shareUpdateToPeer(hash, "status");
								// listen for arbiter response
								db.query("INSERT "+db.getIgnore()+" INTO my_watched_addresses (address) VALUES (?)", [objContract.arbiter_address]);
								cb(null, resp, objContract);
							});
						});
					});
				});
			});
		});
	});
```

**File:** arbiter_contract.js (L465-481)
```javascript
				var arrDefinition =
					["or", [
						["and", [
							["address", offeror_address],
							["address", acceptor_address]
						]],
						[], // placeholders [1][1]
						[],	// placeholders [1][2]
						["and", [
							["address", offeror_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", offeror_address]]
						]],
						["and", [
							["address", acceptor_address],
							["in data feed", [[contract.arbiter_address], "CONTRACT_" + contract.hash, "=", acceptor_address]]
						]]
					]];
```

**File:** arbiter_contract.js (L485-538)
```javascript
				if (isPrivate) { // private asset
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["in data feed", [[acceptor_address], "CONTRACT_DONE_" + contract.hash, "=", offeror_address]]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["in data feed", [[offeror_address], "CONTRACT_DONE_" + contract.hash, "=", acceptor_address]]
					]];
				} else {
					arrDefinition[1][1] = ["and", [
						["address", offeror_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer && !isFixedDen && hasArbStoreCut ? Math.floor(contract.amount * (1 - arbstoreInfo.cut)) : contract.amount,
							address: acceptor_address
						}]
					]];
					arrDefinition[1][2] = ["and", [
						["address", acceptor_address],
						["has", {
							what: "output",
							asset: contract.asset || "base",
							amount: offeror_is_payer || isFixedDen || !hasArbStoreCut ? contract.amount : Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
							address: offeror_address
						}]
					]];
					if (!isFixedDen && hasArbStoreCut) {
						arrDefinition[1][offeror_is_payer ? 1 : 2][1].push(
							["has", {
								what: "output",
								asset: contract.asset || "base",
								amount: contract.amount - Math.floor(contract.amount * (1 - arbstoreInfo.cut)),
								address: arbstoreInfo.address
							}]
						);
					}
					// protect against combining several contracts in a single transaction (if their parties, amounts, and assets are identical, the 'has what' above would satisfy both contracts, allowing the attacker to send the change to themselves)
					arrDefinition[1][1][1].push(
						["not", ["has", {
							what: "input",
							asset: contract.asset || "base",
							address: "other address",
						}]]
					);
					arrDefinition[1][2][1].push(
						["not", ["has", {
							what: "input",
							asset: contract.asset || "base",
							address: "other address",
						}]]
					);
				}
```

**File:** arbiter_contract.js (L692-717)
```javascript
function pay(hash, walletInstance, arrSigningDeviceAddresses, cb) {
	getByHash(hash, function(objContract) {
		if (!objContract.shared_address || objContract.status !== "signed" || !objContract.me_is_payer)
			return cb("contract can't be paid");
		var opts = {
			asset: objContract.asset,
			to_address: objContract.shared_address,
			amount: objContract.amount,
			spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own'
		};
		if (arrSigningDeviceAddresses.length)
			opts.arrSigningDeviceAddresses = arrSigningDeviceAddresses;
		walletInstance.sendMultiPayment(opts, function(err, unit){								
			if (err)
				return cb(err);
			setField(objContract.hash, "status", "paid", function(objContract){
				cb(null, objContract, unit);
			});
			// listen for peer announce to withdraw funds
			storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
				if (assetInfo && assetInfo.is_private)
					db.query("INSERT "+db.getIgnore()+" INTO my_watched_addresses (address) VALUES (?)", [objContract.peer_address]);
			});
		});
	});
}
```

**File:** arbiter_contract.js (L798-814)
```javascript
function parseWinnerFromUnit(contract, objUnit) {
	if (objUnit.authors[0].address !== contract.arbiter_address) {
		return;
	}
	var key = "CONTRACT_" + contract.hash;
	var winner;
	objUnit.messages.forEach(function(message){
		if (message.app !== "data_feed" || !message.payload || !message.payload[key]) {
			return;
		}
		winner = message.payload[key];
	});
	if (!winner || (winner !== contract.my_address && winner !== contract.peer_address)) {
		return;
	}
	return winner;
}
```

**File:** arbiter_contract.js (L878-901)
```javascript
// arbiter response
eventBus.on("new_my_transactions", function(units) {
	units.forEach(function(unit) {
		storage.readUnit(unit, function(objUnit) {
			var address = objUnit.authors[0].address;
			getAllByArbiterAddress(address, function(contracts) {
				contracts.forEach(function(objContract) {
				//	if (objContract.status !== "in_dispute") // the peer might "forget" to send me the in_dispute status update (but we still need to start watching the arbiter's address)
				//		return;
					var winner = parseWinnerFromUnit(objContract, objUnit);
					if (!winner) {
						return;
					}
					var unit = objUnit.unit;
					console.log(`arbiter resolution received for contract ${objContract.hash}, winner: ${winner}, resolution unit: ${unit}, current status: ${objContract.status}`);
					setField(objContract.hash, "resolution_unit", unit);
					setField(objContract.hash, "status", "dispute_resolved", function(objContract) {
						eventBus.emit("arbiter_contract_update", objContract, "status", "dispute_resolved", unit, winner);
					});
				});
			});
		});
	});
});
```

**File:** wallet.js (L909-914)
```javascript
						var isAllowed = objContract.status === "pending" || (objContract.status === 'accepted' && body.status === 'accepted');
						if (!isAllowed)
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
						var objDateCopy = new Date(objContract.creation_date_obj);
						if (objDateCopy.setHours(objDateCopy.getHours(), objDateCopy.getMinutes(), (objDateCopy.getSeconds() + objContract.ttl * 60 * 60)|0) < Date.now())
							return callbacks.ifError("contract already expired");
```
