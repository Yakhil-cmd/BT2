This confirms the arbiter-contract escrow shared address definition has no timeout-based fallback: funds can only move via mutual agreement, arbiter data feed, or arbstore appeal decision. If none of those addresses ever posts, the shared-address funds are permanently locked, mirroring the "keeper never calls unlockOptions" pattern.

### Title
Arbiter-contract escrow funds can be permanently frozen if the arbiter never resolves the dispute - ([File: arbiter_contract.js])

### Summary
In the Obyte arbiter-contract (escrow) flow, funds are held in a shared address whose spending definition only allows release via (a) both parties' joint signature, (b) the arbiter posting a `data_feed`/`CONTRACT_<hash>` resolution, or (c) an arbstore appeal decision. There is no unprivileged, permissionless path or timeout for either party to reclaim funds if the arbiter (a single, off-chain, unprivileged-from-the-protocol's-perspective actor) never acts.

### Finding Description
`deriveSharedAddress()` builds the shared-address AND/OR definition that gates fund release: joint signature by both `offeror_address`/`acceptor_address`, a private-asset `data_feed` "done" flag from the counterparty, or an `in data feed` clause keyed on the arbiter's address (`"CONTRACT_" + contract.hash`) matching either the offeror or acceptor. [1](#0-0) 

When a dispute is opened, resolution depends entirely on the arbiter calling `openDispute`/responding via a `data_feed` unit that names the winner; `parseWinnerFromUnit` only recognizes a resolution unit authored by `contract.arbiter_address`. [2](#0-1) 

If the arbiter never posts this unit, the shared address remains locked (no other authorized signer/data-feed poster exists in the definition) — the losing/uncooperative counterparty can simply refuse to co-sign, and there is no fallback path (e.g., timeout release to depositor) built into the definition. [3](#0-2) 

The only escalation mechanism is `appeal()`, which requires contacting an arbstore service and depends on the contract already being in `dispute_resolved` state — i.e., appeal is only reachable *after* the arbiter has already responded once, so it does not help when the arbiter simply never responds at all. [4](#0-3) 

This is directly analogous to the reported `BufferRouter.resolveQueuedTrades`/`unlockOptions` issue: a single privileged party must actively call/post an action to release user funds, and no permissionless fallback exists if that party is unresponsive.

### Impact Explanation
Funds locked in the arbiter-contract shared address (which can hold bytes or private/public assets, per `contract.amount`/`contract.asset`) become permanently frozen if the designated arbiter address never posts a resolution `data_feed` unit and the counterparty refuses to cooperate on a mutual release. This is a fund-freezing condition reachable purely by an unresponsive but otherwise honest third party (the arbiter), with no code-level (oscript definition) fallback such as an expiry-based unlock clause.

### Likelihood Explanation
Likelihood is moderate: arbiters are chosen by the contracting parties themselves and are trusted third parties, but the protocol provides no enforced SLA or timeout in the on-chain (DAG) definition — nothing prevents an arbiter from going offline, being unreachable, or simply refusing to act after a dispute, especially since disputes by definition involve at least one uncooperative party who has no incentive to also stop the arbiter issue from persisting.

### Recommendation
Add a time-based escape clause to the shared-address definition generated in `deriveSharedAddress()` (e.g., an `["and", [["address", depositor_or_original_payer], ["after", expiry_ts]]]` branch) so that if neither the arbiter nor the counterparty acts within a defined TTL after a dispute is opened, the original payer (or both parties via a pre-agreed default split) can reclaim/release funds unilaterally after the timeout, without requiring the arbiter's cooperation.

### Proof of Concept
1. Two parties (A pays, B receives) create an arbiter contract and pay into the shared address derived by `deriveSharedAddress()`, whose definition only allows release via mutual signature or an `in data feed` clause keyed to `contract.arbiter_address`.
2. A dispute arises; A calls `openDispute()`, notifying the arbiter off-chain via `hub/get_arbstore_url` and an HTTP POST to the arbstore, per `openDispute()`.
3. The arbiter never posts a `CONTRACT_<hash>` data-feed unit (goes offline, ignores the case, or the arbstore service is down).
4. B refuses to co-sign a mutual release (as B is the counterparty in dispute).
5. `parseWinnerFromUnit()` never fires because no qualifying unit from `contract.arbiter_address` exists, so `status` never transitions to `dispute_resolved`, and `appeal()` cannot be invoked (it requires status `dispute_resolved`).
6. The funds in the shared address remain permanently locked; neither party can reclaim them because the underlying shared-address `arrDefinition` has no other unlocking branch.

### Citations

**File:** arbiter_contract.js (L321-355)
```javascript
function appeal(hash, cb) {
	getByHash(hash, function(objContract){
		if (objContract.status !== "dispute_resolved")
			return cb("contract can't be appealed");
		var command = "hub/get_arbstore_url";
		var address = objContract.arbiter_address;
		if (objContract.arbstore_address) {
			command = "hub/get_arbstore_url_by_address";
			address = objContract.arbstore_address;
		}
		device.requestFromHub(command, address, async function(err, url){
			if (err)
				return cb("can't get arbstore url:", err);
			err = await fillArbstoreAddresses(objContract);
			if (err)
				return cb(err);
			device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
				var my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
				var data = JSON.stringify({
					contract_hash: hash,
					my_pairing_code: objContract.my_pairing_code,
					my_address: objContract.my_address,
					contract: {title: objContract.title, text: objContract.text, creation_date: objContract.creation_date, me_is_payer: objContract.me_is_payer, my_address: objContract.my_address, peer_address: objContract.peer_address, my_party_name: objContract.my_party_name, peer_party_name: objContract.peer_party_name, arbiter_address: objContract.arbiter_address, amount: objContract.amount, asset: objContract.asset},
				});
				httpRequest(url, "/api/appeal/new", data, function(err, resp) {
					if (err)
						return cb(err);
					setField(hash, "status", "in_appeal", function(objContract) {
						cb(null, resp, objContract);
					});
				});
			});
		});
	});
}
```

**File:** arbiter_contract.js (L454-481)
```javascript
function deriveSharedAddress(hash, bOfferor, cb) {
	getByHash(hash, function (contract) {
		const offeror_address = bOfferor ? contract.my_address : contract.peer_address;
		const acceptor_address = bOfferor ? contract.peer_address : contract.my_address;
		const offeror_is_payer = bOfferor ? contract.me_is_payer : !contract.me_is_payer;
		const offeror_device_address = bOfferor ? device.getMyDeviceAddress() : contract.peer_device_address;
		const acceptor_device_address = bOfferor ? contract.peer_device_address : device.getMyDeviceAddress();
		arbiters.getArbstoreInfo(contract.arbiter_address, function(err, arbstoreInfo) {
			if (err)
				return cb(err);
			storage.readAssetInfo(db, contract.asset, function (assetInfo) {
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
