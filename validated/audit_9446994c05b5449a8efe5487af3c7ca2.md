Found the closest analog: `arbiter_contract.js`'s `deriveSharedAddress()` function bakes the ArbStore's cut (`arbstoreInfo.cut`) into the shared-address definition at contract-creation time, based on an externally-fetched, mutable value (`arbiters.getArbstoreInfo()`, which is queried live from the ArbStore's HTTP API and cached in `arbStoreInfos`). This is analogous to the Teller bug: a third party (the ArbStore, chosen by the arbiter, not by the two contracting parties) controls a fee ("cut") that gets baked into a payment-splitting condition, and this fee can change between when the payer's counterparty (offeror) fetches it and when the payer actually deposits funds into the shared address. [1](#0-0) [2](#0-1) 

### Title
ArbStore-controlled fee ("cut") is baked into arbiter-contract shared address without borrower/payer consent or pinning, allowing after-the-fact fee inflation - (File: arbiter_contract.js)

### Summary
`deriveSharedAddress()` in `arbiter_contract.js` builds the `["has", {...}]` spending conditions of an arbiter-contract shared address using `arbstoreInfo.cut`, a value fetched live via `arbiters.getArbstoreInfo()` from the ArbStore's HTTP API at the moment the contract is being set up. Neither contracting party (offeror or acceptor) has any protocol-level guarantee that this `cut` value was the one they agreed to, was capped, or matches what was displayed to them earlier; the ArbStore is a party outside of the two-party contract who fully controls this parameter and can change it between contract negotiation and execution.

### Finding Description
When two parties enter into an arbiter contract, `createSharedAddressAndPostUnit()` calls `deriveSharedAddress()`, which fetches the ArbStore info (including `cut`) via `arbiters.getArbstoreInfo(contract.arbiter_address, ...)`. [3](#0-2) 
This value is used directly to compute how much of the contract `amount` goes to the counterparty vs. how much is diverted to `arbstoreInfo.address`: [4](#0-3) 
The `cut` itself comes from `getArbstoreInfo()`, which performs a live HTTPS request to a URL controlled by the arbiter/ArbStore operator (`requestInfoFromArbStore`), and the only validation performed is that `cut` is a number between 0 and 1: [5](#0-4) 
There is no unit-level, signed, or otherwise immutable record of what `cut` value the two contracting parties actually agreed to before the shared address (and its baked-in "has output" conditions) is derived and the payer deposits funds into it via `pay()`. [6](#0-5) 
Because the `cut` is re-fetched from the ArbStore each time `deriveSharedAddress()` runs (subject to an in-memory cache `arbStoreInfos` keyed only by `arbiter_address`, with no expiry tied to the specific contract), an ArbStore operator (who is not one of the two contracting parties, i.e., is a "market owner"-equivalent third party in this Teller-style bug class) can serve a higher `cut` value between the time the parties negotiate/display the expected fee and the time the shared address definition is actually derived/signed and the payer sends funds, causing more of the payer's principal than agreed to be redirected to the ArbStore address instead of the intended counterparty.

### Impact Explanation
If the ArbStore changes (or is compromised to change) the reported `cut`, the payer's deposit into the shared address is split according to the new, higher cut without any prior agreement baked into a stable, verifiable record — effectively diverting part of the payer's principal to the ArbStore's address instead of the counterparty, mirroring the "market owner can manipulate marketplace fee to steal principal" bug class. This directly causes unauthorized loss of funds for the payer (or under-payment to the payee), which is a concrete fund-loss impact.

### Likelihood Explanation
Exploitation requires control of (or compromise of) the ArbStore HTTP endpoint associated with the chosen arbiter, which is a real-world dependency already trusted for other purposes (dispute resolution), but the fee value is not otherwise pinned or attested by the two actual contracting parties, so a malicious or compromised ArbStore operator can carry this out unilaterally without needing cooperation from either party, and without any special network position — it only requires answering the `/api/get_info` request with an altered `cut` at the right time.

### Recommendation
Pin and cryptographically commit to the `arbstoreInfo.cut` value that both parties agreed to (e.g., as part of the signed contract data/hash in `getHash()`), and validate at shared-address-derivation and at contract-view time that the currently fetched `cut` matches the previously agreed value; refuse to derive/sign a shared address (or warn/require re-confirmation) if the ArbStore's live `cut` differs from the one originally shown to and accepted by the parties.

### Proof of Concept
1. Alice (payer) and Bob (payee) select an arbiter whose ArbStore currently reports `cut = 0.01` via `arbiters.getArbstoreInfo()`.
2. Alice's wallet calls `createSharedAddressAndPostUnit()` → `deriveSharedAddress()`, which fetches `arbstoreInfo.cut` and bakes `amount * (1 - cut)` into the shared-address spending condition favoring Bob and the remainder favoring the ArbStore address.
3. Before Alice's wallet actually re-derives the address for signing/paying (`pay()`), or before her cached `arbStoreInfos[arbiter_address]` entry is refreshed, the ArbStore operator changes the reported `cut` to `0.50` on its `/api/get_info` endpoint.
4. On the next `deriveSharedAddress()` call (e.g., a retry, a new session, or once the in-memory cache in `arbiters.js` is cleared/expired by a restart), the shared address is derived with `cut = 0.50`, redirecting half of the contract amount to the ArbStore instead of the ~1% originally agreed, and Alice's payment into this shared address is split accordingly — with no on-chain or protocol-level artifact proving what `cut` was actually agreed to.

### Citations

**File:** arbiters.js (L51-79)
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
```

**File:** arbiter_contract.js (L454-522)
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
				var isPrivate = assetInfo && assetInfo.is_private;
				var isFixedDen = assetInfo && assetInfo.fixed_denominations;
				var hasArbStoreCut = arbstoreInfo.cut > 0;
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
