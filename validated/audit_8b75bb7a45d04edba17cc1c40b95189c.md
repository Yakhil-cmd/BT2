### Title
Headers-commission and witnessing rewards sent to an AA address become permanently unspendable - ([File: validation.js])

### Summary
Any multi-authored unit can freely designate an Autonomous Agent (AA) address as an `earned_headers_commission_recipients` entry, and any address (including an AA) can accumulate `witnessing_outputs` earnings. However, ocore's validation logic explicitly forbids AA-generated response units from containing `headers_commission` or `witnessing` type inputs, and AAs have no private key to author an ordinary signed unit. The combination permanently locks any headers commission or witnessing reward credited to an AA address, mirroring the reported Perennial "fee locked to an address that cannot claim it" bug class.

### Finding Description
`validateHeadersCommissionRecipients` only checks that a recipient address is a syntactically valid address and that the shares sum to 100 — it never checks whether the address belongs to an AA: [1](#0-0) 

Once a unit lists an AA address as a headers-commission recipient (or once the AA address is simply named as an author whose child unit wins headers commission), `headers_commission.js` distributes the earnings to that address via `headers_commission_outputs`/`headers_commission_contributions`, with no restriction excluding AA addresses: [2](#0-1) 

The only way to actually spend these earnings is to include a payment input of `type: "headers_commission"` or `type: "witnessing"` in a unit authored by that address. But `validatePaymentInputsAndOutputs` explicitly bounces any such input when the unit is an AA-generated (bounce/response) unit: [3](#0-2) 

AAs can only ever produce response units through `aa_composer.js`'s `sendUnit`, which builds units with `authors: [{ address: address }]` and never with a real signature (AAs have no private keys, only an `autonomous agent` definition) — so they cannot author a normal (non-AA) unit either to spend commission-type inputs: [4](#0-3) 

As a result, once bytes/rewards are earned as `headers_commission` or `witnessing` credited to an AA address, there is no code path by which that AA can ever construct a valid spending unit for them: AA-authored units reject the input type, and the AA can't author a plain signed unit at all.

### Impact Explanation
Headers commissions and witnessing rewards attributable to an AA address (e.g. because someone named the AA in `earned_headers_commission_recipients`, or an AA happens to be a witness) become permanently frozen bytes that no one can ever move — a straightforward, irreversible fund-freezing condition analogous to the cited "protocol fee locked" issue, where funds are routed to an address structurally incapable of claiming them.

### Likelihood Explanation
Triggering this requires only posting an ordinary multi-authored unit (a capability any unprivileged user has) that lists a known AA address in `earned_headers_commission_recipients`, or simply having an AA address function as a witness that occasionally wins headers commission. No special privileges, malicious peers, or protocol-level exploits are needed — it is reachable purely through standard unit composition.

### Recommendation
Reject `earned_headers_commission_recipients` entries (and, ideally, witnessing-eligible addresses) that resolve to AA addresses during validation (e.g., extend `validateHeadersCommissionRecipients` to check `storage`/`aa_addresses` similar to the existing `checkNotAAs` helper used elsewhere), or alternatively allow AA-authored units to spend `headers_commission`/`witnessing` inputs (e.g., by auto-including them in the AA's outgoing payment the way regular bytes balance is spent) so earnings credited to AA addresses are not permanently stranded.

### Proof of Concept
1. Two regular users co-author a unit whose messages include a payment such that the unit is eligible to win headers commission on its parent(s).
2. In `earned_headers_commission_recipients`, list an AA address (any deployed AA) with `earned_headers_commission_share: 100`.
3. `validateHeadersCommissionRecipients` accepts this (only format/sum are checked) — see [1](#0-0) .
4. Once the unit stabilizes and wins the header commission race, `headers_commission.js` credits the AA address in `headers_commission_outputs` — see [2](#0-1) .
5. Attempt to spend this via an AA-generated unit: blocked by `if (objValidationState.bAA) return cb(type+" in AA")` in `validation.js` — see [3](#0-2) .
6. There is no other mechanism for the AA to author a signed non-AA unit (it has no private key), so the credited amount can never be spent — permanently locked.

### Citations

**File:** validation.js (L1101-1126)
```javascript
function validateHeadersCommissionRecipients(objUnit, cb){
	if (objUnit.authors.length > 1 && typeof objUnit.earned_headers_commission_recipients !== "object")
		return cb("must specify earned_headers_commission_recipients when more than 1 author");
	if ("earned_headers_commission_recipients" in objUnit){
		if (!isNonemptyArray(objUnit.earned_headers_commission_recipients))
			return cb("empty earned_headers_commission_recipients array");
		var total_earned_headers_commission_share = 0;
		var prev_address = "";
		for (var i=0; i<objUnit.earned_headers_commission_recipients.length; i++){
			var recipient = objUnit.earned_headers_commission_recipients[i];
			if (!isPositiveInteger(recipient.earned_headers_commission_share))
				return cb("earned_headers_commission_share must be positive integer");
			if (hasFieldsExcept(recipient, ["address", "earned_headers_commission_share"]))
				return cb("unknown fields in recipient");
			if (!isValidAddress(recipient.address))
				return cb("invalid recipient address checksum");
			if (recipient.address <= prev_address)
				return cb("recipient list must be sorted by address");
			total_earned_headers_commission_share += recipient.earned_headers_commission_share;
			prev_address = recipient.address;
		}
		if (total_earned_headers_commission_share !== 100)
			return cb("sum of earned_headers_commission_share is not 100");
	}
	cb();
}
```

**File:** validation.js (L2529-2532)
```javascript
				case "headers_commission":
				case "witnessing":
					if (objValidationState.bAA)
						return cb(type+" in AA");
```

**File:** headers_commission.js (L144-188)
```javascript
						var assocWonAmounts = {}; // amounts won, indexed by child unit who won the hc, and payer unit
						for (var payer_unit in assocChildrenInfos){
							var headers_commission = assocChildrenInfos[payer_unit].headers_commission;
							var winnerChildInfo = getWinnerInfo(assocChildrenInfos[payer_unit].children);
							var child_unit = winnerChildInfo.child_unit;
							if (!assocWonAmounts[child_unit])
								assocWonAmounts[child_unit] = {};
							assocWonAmounts[child_unit][payer_unit] = headers_commission;
						}
						//console.log(assocWonAmounts);
						var arrWinnerUnits = Object.keys(assocWonAmounts);
						if (arrWinnerUnits.length === 0)
							return cb();
						var strWinnerUnitsList = arrWinnerUnits.map(db.escape).join(', ');
						conn.cquery(
							"SELECT \n\
								unit_authors.unit, \n\
								unit_authors.address, \n\
								100 AS earned_headers_commission_share \n\
							FROM unit_authors \n\
							LEFT JOIN earned_headers_commission_recipients USING(unit) \n\
							WHERE unit_authors.unit IN("+strWinnerUnitsList+") AND earned_headers_commission_recipients.unit IS NULL \n\
							UNION ALL \n\
							SELECT \n\
								unit, \n\
								address, \n\
								earned_headers_commission_share \n\
							FROM earned_headers_commission_recipients \n\
							WHERE unit IN("+strWinnerUnitsList+")",
							function(profit_distribution_rows){
								// in-memory
								var arrValuesRAM = [];
								for (var child_unit in assocWonAmounts){
									var objUnit = storage.assocStableUnits[child_unit];
									for (var payer_unit in assocWonAmounts[child_unit]){
										var full_amount = assocWonAmounts[child_unit][payer_unit];
										if (objUnit.assocEarnedHeadersCommissionRecipients) { // multiple authors or recipient is another address
											for (var address in objUnit.assocEarnedHeadersCommissionRecipients) {
												var share = objUnit.assocEarnedHeadersCommissionRecipients[address];
												var amount = Math.round(full_amount * share / 100.0);
												arrValuesRAM.push("('"+payer_unit+"', '"+address+"', "+amount+")");
											};
										} else
											arrValuesRAM.push("('"+payer_unit+"', '"+objUnit.author_addresses[0]+"', "+full_amount+")");
									}
```

**File:** aa_composer.js (L1369-1377)
```javascript
				objUnit = {
					version: mci >= constants.v4UpgradeMci ? constants.version : (bWithKeys ? constants.version3 : constants.versionWithoutKeySizes), // we should actually use last_ball_mci
					alt: constants.alt,
					timestamp: objMcUnit.timestamp,
					messages: messages,
					authors: [{ address: address }],
					last_ball_unit: objMcUnit.last_ball_unit,
					last_ball: objMcUnit.last_ball,
				};
```
