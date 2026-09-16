## Finding: ArbStore service fee ("cut") can be bypassed by both contracting parties colluding on an arbiter contract's shared address

### Title
ArbStore dispute-resolution fee can be bypassed by mutual signing on the arbiter-contract shared address - (File: arbiter_contract.js)

### Summary
`arbiter_contract.js`'s `deriveSharedAddress()` builds the address definition that both parties of an arbiter contract use to hold and later release the contract funds. The definition is meant to guarantee that, whenever the contract completes normally, the ArbStore's `cut` (its service fee for offering dispute resolution) is paid out alongside the peer's payment. However, one of the four alternative branches of the definition allows the funds to be released by the mere joint signatures of the two contracting parties, with **no output/amount restriction at all**, letting the two parties bypass the fee entirely — directly analogous to the reported `FixedStrikeOptionTeller` issue where a fee is skipped whenever sender and receiver collude.

### Finding Description
`deriveSharedAddress()` constructs an `"or"` definition with several alternative spending paths: [1](#0-0) 

Branch `[0]` is simply:
```
["and", [["address", offeror_address], ["address", acceptor_address]]]
```
i.e. it only requires the signatures of both parties — it carries **no `has output` clause** enforcing payment of the ArbStore's cut.

The fee-enforcing logic only lives in the other branches, `[1][1]` and `[1][2]`, which are populated conditionally on `hasArbStoreCut` and require a `"has" {what: "output", ..., address: arbstoreInfo.address}` clause when the contract is paid out to the winning party: [2](#0-1) 

The intended, "happy path" flow for finishing a contract without a dispute is `complete()`, which explicitly builds `peer_amount` + `arbstore_amount` outputs based on the shared-address definition it expects to find: [3](#0-2) 

But because the underlying shared address is defined with the `"or"` branch `[0]` (mutual signatures only, no output constraint), nothing on the protocol/definition level actually forces the fee to be paid. Both parties (offeror and acceptor) can instead co-sign an arbitrary payment out of the shared address — sending the *entire* held balance directly to whichever address they like, skipping the ArbStore output completely. Since this branch requires both parties' authentifiers exactly like the normal, expected completion flow, an integrator or one of the users can simply avoid calling the standard `complete()` composition logic and instead post a custom payment authorized under branch `[0]`.

This mirrors the reported bug class precisely: the fee-enforcing condition is only encoded in one code path (like `FixedStrikeOptionTeller` charging a fee unless `sender == receiver`), while an alternative, equally valid path (mutual co-signing, analogous to a receiver contract controlled by the same party) exists and has no such restriction.

### Impact Explanation
The ArbStore is meant to be compensated (via `cut`) for providing dispute-resolution services whenever a contract completes through the shared address it helped set up. By using the unrestricted mutual-signing branch of the definition, both contracting parties can withdraw the entire contract amount without ever paying the ArbStore its fee, denying it its earned revenue on every single contract. This is systemic — any pair of colluding parties (which is the ordinary, non-adversarial case since both benefit from avoiding the fee) can always take this path, meaning the fee mechanism provides no real guarantee at the protocol level.

### Likelihood Explanation
High. There is no cost or extra sophistication needed by the colluding parties: they already possess both required signatures needed for the "happy path" completion in the first place, so signing a self-serving payment through branch `[0]` instead of calling `complete()` is trivial and requires no special privilege.

### Recommendation
Remove the unconditional mutual-signing branch (`[0]`) from the shared address definition when `hasArbStoreCut` is true, or otherwise fold the ArbStore's `"has output"` cut requirement into every spending path of the definition (including the plain mutual-signature branch), so that the fee output cannot be omitted regardless of which branch of the `"or"` is used to authorize the spend.

### Proof of Concept
1. Two parties, Alice (offeror/payer) and Bob (acceptor), create an arbiter contract via `createSharedAddressAndPostUnit`, whose shared address definition is produced by `deriveSharedAddress` and includes the ArbStore `cut` clause in branches `[1][1]`/`[1][2]`.
2. Alice pays the contract amount into the shared address via `pay()`.
3. Instead of calling `complete()` (which would build outputs paying both Bob and the ArbStore), Alice and Bob jointly craft and sign a payment unit spending the full balance of the shared address straight to Bob's address, authorized under definition branch `["and", [["address", offeror_address], ["address", acceptor_address]]]` (i.e., both simply co-sign).
4. This unit is valid because it satisfies branch `[0]` of the `"or"` definition, which has no output constraint — the ArbStore's `cut` output is never required, so no fee is paid. [1](#0-0)

### Citations

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

**File:** arbiter_contract.js (L746-772)
```javascript
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
```
