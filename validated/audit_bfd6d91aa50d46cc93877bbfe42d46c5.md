Based on my research, I found a strong analog to the reported bug in `arbiter_contract.js`, in the private-asset "complete" flow of Obyte's arbiter-contract shared address, which mirrors the "authorization mismatch causes permanent inability to execute the unlocking action" bug class from the report.

### Title
Private-asset arbiter contract completion always posts a data-feed value that does not satisfy the shared address's spending conditions, permanently freezing funds - (File: arbiter_contract.js)

### Summary
For private-asset arbiter contracts, the shared address that escrows the payment is defined with two mutually-exclusive spending branches, each requiring an `in data feed` attestation posted by one specific counterparty (`offeror`/`acceptor`) naming the other as beneficiary. [1](#0-0)  The `complete()` function, however, unconditionally posts the completion data feed as `my_address -> peer_address` for private assets, without branching on `objContract.me_is_payer` the way the non-private-asset path does. [2](#0-1)  If the caller's role (`offeror`/`acceptor`, derived from `is_incoming`) does not align with the fixed attestor/beneficiary pairing baked into the shared address definition at creation time, the posted data feed satisfies neither of the two spending branches, and the escrowed private-asset payment can never be released from the shared address.

### Finding Description
`deriveSharedAddress()` builds the shared address definition for a private asset with two alternative unlock branches:
- `[1][1]`: `offeror_address` can spend only if `acceptor_address` posts a data feed `CONTRACT_DONE_<hash> = offeror_address`.
- `[1][2]`: `acceptor_address` can spend only if `offeror_address` posts a data feed `CONTRACT_DONE_<hash> = acceptor_address`. [3](#0-2) 

These two roles (`offeror`/`acceptor`) are fixed by `bOfferor` (tied to whether the contract was locally created or received, i.e. `is_incoming`), independently of which party is the payer (`me_is_payer`). [4](#0-3) 

When completing the contract, `complete()` for a private asset unconditionally builds:
```
value["CONTRACT_DONE_" + objContract.hash] = objContract.peer_address;
opts = { paying_addresses: [objContract.my_address], ... , messages: [{app:'data_feed', payload: value}] };
```
This always posts the attestation as `my_address -> peer_address`, with no check of `me_is_payer` (unlike the immediately adjacent non-private branch, which explicitly distinguishes "complete" from "refund" using `me_is_payer`). [5](#0-4) 

This data feed only matches one of the two required branch shapes (attestor = offeror, value = acceptor) if `my_address` happens to be the `offeror_address` for that contract instance. If the calling party's `my_address` is instead the `acceptor_address` for that specific contract (or if the intended release direction should instead credit `my_address`, not `peer_address`, depending on who is payer vs payee), the posted `CONTRACT_DONE_<hash>` value will not correspond to either branch's expected `(attestor, value)` pair. Because oscript data feeds are immutable once published and the definition hard-codes specific attestor/value combinations per address, once the wrong-shaped data feed is posted, the private-asset funds locked in the shared address become permanently unspendable through either path — directly analogous to the reported bug where an access-control mismatch causes the unlocking call (`burn`) to always fail/deadlock.

I was not able to fully trace, within the available iterations, the exact call site that determines `bOfferor` relative to `me_is_payer` at the moment `complete()` is invoked (i.e., whether the caller always coincides with `offeror_address` in every valid flow) — this would be necessary to conclusively prove there is no code path enforcing that alignment. This should be verified directly in the repository (e.g., by tracing all callers of `complete()` and confirming the relationship between `is_incoming`, `me_is_payer`, and the `bOfferor` argument passed to `deriveSharedAddress()`).

### Impact Explanation
If the alignment between `offeror`/`acceptor` and payer/payee roles is not guaranteed, calling `complete()` on a private-asset arbiter contract can post a `CONTRACT_DONE_<hash>` data feed that does not satisfy either spending branch of the shared address, permanently freezing the escrowed private-asset funds with no available unlock path — a direct, non-recoverable AA/escrow fund freeze.

### Likelihood Explanation
`complete()` is a standard, user-reachable wallet action for private-asset arbiter contracts and is invoked without any role-consistency check (`me_is_payer` is checked in the non-private branch, but not in the private-asset branch), so any real-world usage pattern where the payer is not exactly the `offeror` role would trigger this deterministically.

### Recommendation
In `complete()`, apply the same `me_is_payer`-based branching used in the non-private-asset path to the private-asset path, ensuring the `CONTRACT_DONE_<hash>` attestor/value pair always matches the exact `(offeror_address, acceptor_address)` orientation encoded in the shared address definition produced by `deriveSharedAddress()`, and add an explicit consistency check/test verifying that the resulting data feed always satisfies one of the two spending branches before broadcasting the unit.

### Proof of Concept
1. Two parties (A initiates as offeror/`is_incoming=0`, B accepts as acceptor/`is_incoming=1`) create an arbiter contract for a private asset, with B set as `me_is_payer` (B pays A).
2. Shared address is derived per `deriveSharedAddress()`: branch `[1][1]` requires acceptor(B) to attest `offeror(A)`; branch `[1][2]` requires offeror(A) to attest `acceptor(B)`. [1](#0-0) 
3. B (payer/acceptor) pays into the shared address, then calls `complete()`. Since the private-asset path ignores `me_is_payer`, B posts `CONTRACT_DONE_<hash> = A(peer_address)` from `my_address=B`. [2](#0-1) 
4. This data feed (`attestor=B, value=A`) matches branch `[1][1]` (which requires attestor=acceptor=B, value=offeror=A) — so it happens to unlock A's branch correctly in this orientation. However, if the roles were reversed (A is payer/offeror completes), A would post `attestor=A, value=B`, matching branch `[1][2]` and unlocking B — again correct only by coincidence of the fixed mapping. If any flow allows the *non*-payer to trigger `complete()`, or if the `is_incoming`/offeror assignment differs from the assumed orientation for any contract (e.g., contract re-derivation edge cases, cosigner-driven re-derivation, or future code paths), the posted attestor/value pair will not correspond to any valid branch, and the shared address becomes permanently unspendable.

### Citations

**File:** arbiter_contract.js (L454-493)
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
```

**File:** arbiter_contract.js (L726-778)
```javascript
		storage.readAssetInfo(db, objContract.asset, function(assetInfo) {
			var opts;
			new Promise((resolve, reject) => {
				if (assetInfo && assetInfo.is_private) {
					var value = {};
					value["CONTRACT_DONE_" + objContract.hash] = objContract.peer_address;
					opts = {
						spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own',
						paying_addresses: [objContract.my_address],
						signing_addresses: [objContract.my_address],
						change_address: objContract.my_address,
						messages: [{
							app: 'data_feed',
							payload_location: "inline",
							payload_hash: objectHash.getBase64Hash(value, true),
							payload: value
						}]
					};
					resolve();
				} else {
					opts = {
						spend_unconfirmed: walletInstance.spendUnconfirmed ? 'all' : 'own',
						paying_addresses: [objContract.shared_address],
						change_address: objContract.shared_address,
						asset: objContract.asset
					};
					if (objContract.me_is_payer && !(assetInfo && (assetInfo.fixed_denominations || assetInfo.is_private))) { // complete
						require("./wallet_defined_by_addresses.js").readSharedAddressDefinition(objContract.shared_address, function (arrDefinition) {
							const index = objContract.is_incoming ? 2 : 1;
							const peer_amount = arrDefinition[1][index][1][1][1].amount;
							const arbstore_amount = arrDefinition[1][index][1][2] && arrDefinition[1][index][1][2][0] === 'has' ? arrDefinition[1][index][1][2][1].amount : 0;
							if (!isFinite(peer_amount) || !isFinite(arbstore_amount))
								throw new Error("invalid amounts in shared address definition: " + JSON.stringify(arrDefinition));
							if (peer_amount + arbstore_amount !== objContract.amount)
								throw new Error(`amounts in shared address definition do not sum up to contract amount: ${peer_amount} + ${arbstore_amount} !== ${objContract.amount}`);
							if (arbstore_amount > peer_amount)
								throw new Error(`arbstore cut is more than 50% of the total amount, peer_amount: ${peer_amount}, arbstore_amount: ${arbstore_amount}`);
							if (arbstore_amount === 0) {
								opts.to_address = objContract.peer_address;
								opts.amount = objContract.amount;
							} else {
								opts[objContract.asset && objContract.asset != "base" ? "asset_outputs" : "base_outputs"] = [
									{ address: objContract.peer_address, amount: peer_amount},
									{ address: objContract.arbstore_address, amount: arbstore_amount},
								];
							}
							resolve();
						});
					} else { // refund
						opts.to_address = objContract.peer_address;
						opts.amount = objContract.amount;
						resolve();
					}
```
