### Title
Missing check that `offeror_address != acceptor_address` in arbiter-contract shared-address derivation collapses the two-party consent into a single-key requirement - (File: arbiter_contract.js)

### Summary
`deriveSharedAddress()` in `arbiter_contract.js` builds the escrow shared-address definition from `contract.my_address` and `contract.peer_address` without ever verifying that these two addresses are actually distinct, mirroring the root cause of the referenced report: matching/contract-composing logic that trusts two supposedly-independent parties without checking they are not in fact the same actor.

### Finding Description
`deriveSharedAddress()` computes `offeror_address` and `acceptor_address` purely from the stored `my_address`/`peer_address` fields of the arbiter contract record and plugs them directly into the definition template as two separate co-signers: [1](#0-0) 
Neither this function nor the contract creation/acceptance path (`createAndSend`, `store`, `respond`) enforces `offeror_address !== acceptor_address` anywhere in the file; a `grep` for such an inequality check across the file only turns up an unrelated comparison used later in a dispute-request handler in `wallet.js`, not in the contract/escrow-creation flow itself.

The resulting definition's mutual-consent branch is:
```
["and", [["address", offeror_address], ["address", acceptor_address]]]
```
which is intended to require independent signatures from two different parties before the escrowed funds can be spent from the shared address. If `offeror_address` and `acceptor_address` are equal (i.e., the "peer" of the contract is, from a data standpoint, the same address as "my_address"), this branch degenerates to requiring only a single signature by that one address, and the "protect against combining several contracts" mitigation (the `["not", ["has", {what: "input", address: "other address"}]]` clause) does nothing to prevent this, since it only guards against combining multiple *distinct* contracts, not a contract whose two roles share one key: [2](#0-1) 
This is directly analogous to the audited finding: order/contract matching logic validates shape and amounts of the two sides but never checks that the two parties are actually different principals, so a data-level collision between "buyer/offeror" and "seller/acceptor" silently breaks the two-party guarantee the mechanism is built on.

### Impact Explanation
The arbiter-contract shared address is meant to enforce that release of escrowed funds requires cooperative signing by two distinct counterparties (or, alternatively, arbiter/data-feed resolution). If the two roles resolve to the same address — whether through a malformed/malicious contract offer accepted without validation, or through a bug in the wallet UI/flow that lets `my_address` equal `peer_address` — the "and" condition intended to require mutual agreement collapses to a single signature, defeating the two-party consent guarantee the contract escrow relies on and letting one party unilaterally control fund release from what was supposed to be a jointly-controlled address.

### Likelihood Explanation
Exploitation requires a specific data condition (offeror and acceptor addresses being identical for a given contract instance) to be accepted and persisted by both sides of a paired-device negotiation without being rejected, similar to how the original report requires the off-chain matching engine to feed a specific (wrong) combination of orders. Because `arbiter_contract.js` never rejects this condition at any stage (`createAndSend`, `store`, `respond`, `deriveSharedAddress`), the missing check is a genuine gap rather than a defense-in-depth omission, but it depends on how the paired-device flow can be induced to set matching addresses, which could not be fully traced within the available exploration (the exact device-message handler in `wallet.js` that populates `my_address`/`peer_address` on the receiving side of `arbiter_contract_offer` was not confirmed before the tool budget was exhausted).

### Recommendation
Add an explicit check in `arbiter_contract.js` (e.g., in `createAndSend`, `store`, and/or `deriveSharedAddress`) that rejects any contract where `contract.my_address === contract.peer_address`, mirroring the recommended fix in the source report ("ensure seller != buyer").

### Proof of Concept
Not independently reproduced on-chain; derived by static analysis of `deriveSharedAddress()` showing the definition template lacks an `offeror_address !== acceptor_address` guard: [3](#0-2) 
Full confirmation of the end-to-end exploit path (how `my_address`/`peer_address` are populated on the receiving side of an `arbiter_contract_offer` device message) requires reviewing the corresponding handler in `wallet.js`, which could not be completed within the available tool budget — this should be verified in a full Devin session with unrestricted repository access.

### Citations

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

**File:** arbiter_contract.js (L523-537)
```javascript
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
```
