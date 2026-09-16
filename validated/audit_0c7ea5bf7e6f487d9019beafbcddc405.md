### Title
Arbiter contract escrow split (`cut`) is fetched live and not committed at contract-agreement time, allowing the ArbStore to change fee terms after the deal is struck - ([File: arbiter_contract.js])

### Summary
`arbiter_contract.js`'s `deriveSharedAddress()` builds the escrow (shared) address definition for an arbitrated trade using an ArbStore service-fee value (`cut`) that is fetched live via `arbiters.getArbstoreInfo()` at the moment the address is derived, rather than being part of the contract terms that both parties cryptographically committed to (hashed) when they agreed to the deal. This mirrors the reported "Marketplace" bug class: a value that determines how much of a payer's/payee's funds ends up where can be changed unilaterally by a third party (here, the ArbStore) between commitment (offer/accept) and finalization (derivation of the spending address), with no on-chain or protocol-level check that the value used matches what was agreed.

### Finding Description
When two parties negotiate an arbitrated contract, the contract object is hashed and signed over a fixed set of fields — `title`, `text`, `my_address`, `peer_address`, `creation_date`, `my_party_name`, `peer_party_name`, `me_is_payer`, `arbiter_address`, `amount`, `asset` (see the hash reconstruction in the dispute-request handler): [1](#0-0) 

Notably, the ArbStore's `cut` (the escrow/service fee percentage) is **not** part of this hash. The `cut` is only pulled in later, when the shared (escrow) address is actually derived, via a live HTTP call to the ArbStore: [2](#0-1) 

`deriveSharedAddress()` then bakes this freshly-fetched `cut` value directly into the immutable spend-condition (`"has"` output amount) of the escrow address definition, determining exactly how the deposited funds must be split between offeror, acceptor, and the ArbStore: [3](#0-2) 

Both parties derive this address independently and on different devices/nodes: the offeror when creating and funding the address (`createSharedAddressAndPostUnit`), and the acceptor later when verifying the address it received (`handleReceivedSharedAddress`): [4](#0-3) [5](#0-4) 

Because `cut` is fetched independently by each party at different times (each node maintains its own `arbStoreInfos` cache), and is not fixed by the hash-committed contract terms, the ArbStore can change its published `cut` between the time the deal was negotiated (and shown to the user) and the time the escrow address is actually derived and funded. The resulting on-chain spend conditions will reflect whatever `cut` was live at derivation time — not the value the parties believed they agreed to. Once funds are sent to the resulting `shared_address`, the split is permanently fixed by that address's (immutable) definition; there is no commitment check comparing the `cut` used against a value the counterparty explicitly agreed to.

### Impact Explanation
This is directly analogous to the reported bug: a mutable "term" (price/cut) controlled by one party (the ArbStore, structurally similar to the token owner in the external report) determines how another party's funds are ultimately allocated, and the protocol never requires the payer/payee to commit to and validate an *expected* cut before value is locked into a spending condition. If the ArbStore raises its cut between contract negotiation and address derivation, the ArbStore receives a larger share of the escrowed funds than either counterparty agreed to, at the direct expense of the payer or payee — a form of unauthorized fund reallocation from the user's principal via the shared-address spend conditions. Because the shared address hash is derived from the definition (which embeds the fee split), any change in `cut` also changes the resulting address; a race between two nodes fetching `cut` at different instants can also cause the offeror's derived address (already funded) to mismatch what the acceptor independently computes, creating disagreement about the correctness of the escrow terms/funds allocation between the two legitimate parties.

### Likelihood Explanation
The ArbStore is queried over plain HTTPS via a URL obtained from the hub (`hub/get_arbstore_url`) and there is no expiry, freshness, or replay binding between the fee quote and the specific contract; only a naive per-process cache (`arbStoreInfos`) is used. Any legitimate/compromised ArbStore operator can change the `/api/get_info` response's `cut` field at will (it only needs `0 <= cut < 1`), and the offeror and acceptor nodes will very plausibly fetch it at different points in time (offeror derives it when creating and funding the address; acceptor derives and verifies it independently, often after some delay). No signature or timestamp ties the `cut` to a specific contract's hash, so this is straightforward to trigger without any network-level or peer-compromise conditions — an ordinary escrow flow with a slow acceptor or an ArbStore that updates its published cut is sufficient.

### Recommendation
Include the ArbStore `cut` (and ArbStore `address`) as explicit fields in the arbiter contract object that both parties sign/hash at offer time (alongside `amount`, `asset`, `arbiter_address`), and have `deriveSharedAddress()` use only the committed `cut`/`address` values instead of re-fetching live ArbStore info at derivation time. If a fresh cut must be fetched for freshness reasons, validate that it matches the value the parties agreed to before proceeding, and abort/re-negotiate (rather than silently deriving a different escrow address) if it has changed.

### Proof of Concept
1. Alice and Bob negotiate an arbiter contract for `amount=1000` (asset `base`), with `arbiter_address=Carol`, hashed and exchanged per `getHash()` semantics (fields shown in `wallet.js:767-779`); at this moment ArbStore reports `cut=0.01` to both.
2. Alice (offeror) accepts and calls `createSharedAddressAndPostUnit`, which invokes `deriveSharedAddress()`; the ArbStore's `/api/get_info` is queried again and now returns `cut=0.10` (changed by the ArbStore operator between steps 1 and 2). [6](#0-5) 
3. The resulting shared-address definition bakes in the new 10% cut: Bob's expected payout output is computed as `Math.floor(contract.amount * (1 - arbstoreInfo.cut))`, i.e. 900 instead of the 990 both parties expected under the originally-quoted 1% cut. [7](#0-6) 
4. Alice funds this shared address for the full `amount`. When Bob is later paid out, he receives only 900 instead of 990 — the extra 90 is unilaterally captured by the ArbStore, with no on-chain or protocol check that the split matches the fee level originally shown to and agreed by the parties.

### Citations

**File:** wallet.js (L767-780)
```javascript
				var expectedContractHash = arbiter_contract.getHash({
					title: contractContent.title,
					text: contractContent.text,
					my_address: body.my_address,
					peer_address: body.peer_address,
					creation_date: contractContent.creation_date,
					my_party_name: contractContent.plaintiff_party_name,
					peer_party_name: contractContent.respondent_party_name,
					me_is_payer: body.me_is_payer,
					arbiter_address: body.arbiter_address,
					amount: body.amount,
					asset: body.asset
				});
				if (body.contract_hash !== expectedContractHash)
```

**File:** arbiters.js (L51-80)
```javascript
function getArbstoreInfo(arbiter_address, cb) {
	if (!cb)
		return new Promise(function(resolve, reject){
			getArbstoreInfo(arbiter_address, function(err, info){
				if (err) return reject(err);
				resolve(info);
			});
		});
	if (arbStoreInfos[arbiter_address]) return cb(null, arbStoreInfos[arbiter_address]);
	device.requestFromHub("hub/get_arbstore_url", arbiter_address, function(err, url){
		if (err) {
			return cb(err);
		}
		if (!validationUtils.isNonemptyString(url))
			return cb("invalid url received from hub");
		requestInfoFromArbStore(url+'/api/get_info', function(err, info){
			if (err)
				return cb(err);
			if (!validationUtils.isNonemptyObject(info))
				return cb("invalid info received from arbstore");
			const cut = parseFloat(info.cut);
			if (!info.address || !validationUtils.isValidAddress(info.address) || isNaN(cut) || cut < 0 || cut >= 1) {
				return cb("malformed info received from ArbStore");
			}
			info.url = url;
			arbStoreInfos[arbiter_address] = info;
			cb(null, info);
		});
	});
}
```

**File:** arbiter_contract.js (L461-484)
```javascript
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
				var isPrivate = assetInfo && assetInfo.is_private;
				var isFixedDen = assetInfo && assetInfo.fixed_denominations;
				var hasArbStoreCut = arbstoreInfo.cut > 0;
```

**File:** arbiter_contract.js (L494-522)
```javascript
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
```

**File:** arbiter_contract.js (L577-591)
```javascript
// walletInstance should have "sendMultiPayment" function with appropriate signer inside
function createSharedAddressAndPostUnit(hash, walletInstance, cb) {
	deriveSharedAddress(hash, true, function(err, arrDefinition, assocSignersByPath) {
		if (err)
			return cb(err);
		require("./wallet_defined_by_addresses.js").createNewSharedAddress(arrDefinition, assocSignersByPath, {
			ifError: function(err){
				cb(err);
			},
			ifOk: function(shared_address){
				setField(hash, "shared_address", shared_address, async function(contract) {
					const err = await fillArbstoreAddresses(contract);
					if (err)
						return cb(err);
					// share this contract to my cosigners for them to show proper ask dialog
```

**File:** arbiter_contract.js (L632-657)
```javascript
function handleReceivedSharedAddress(hash, shared_address, from_cosigner, retry_count = 0) {
	console.log(`received shared address ${shared_address} for arbiter contract ${hash} from peer`);
	db.query("SELECT 1 FROM shared_addresses WHERE shared_address=?", [shared_address], function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`shared address ${shared_address} not found in db after 10 retries, giving up`);
			console.log(`shared address ${shared_address} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
		}
		console.log(`shared address ${shared_address} found in db, deriving shared address definition to verify it matches the received one`);
		deriveSharedAddress(hash, false, function (err, arrDefinition, assocSignersByPath) {
			if (err) {
				if (retry_count >= 10)
					return console.log(`failed derivation of shared address ${shared_address} after 10 retries, giving up`, err);
				console.log("error deriving shared address definition, will retry in 30 seconds", err);
				return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
			}
			const expected_shared_address = objectHash.getChash160(arrDefinition);
			if (expected_shared_address !== shared_address)
				return console.log(`expected shared address ${expected_shared_address} does not match received from offeror ${shared_address}`, JSON.stringify(arrDefinition, null, 2));
			console.log(`shared address ${expected_shared_address} matches the received one, setting it to the contract and sharing with cosigners`);
			setField(hash, "shared_address", shared_address, function (contract) {
				eventBus.emit("arbiter_contract_update", contract, "shared_address", shared_address);
			}, from_cosigner);
		});
	});
```
