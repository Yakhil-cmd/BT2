### Title
Headers commission and witnessing rewards earned by an AA address become permanently unredeemable - (File: `validation.js`)

### Summary
This mirrors the AAVE `AaveStrategy` bug class: value automatically accrues to an address through a protocol-native reward mechanism, but the only code path that would let that address reclaim the value is explicitly blocked, permanently freezing funds. In ocore, any AA response unit is a normal single-authored unit and can legitimately win headers commission (as the "best child" of one of its selected parents) or paid-witnessing commission (if the AA's address happens to be a witness) exactly like any other address, crediting bytes to the AA address via `headers_commission_outputs` / `witnessing_outputs`. But AA units are explicitly forbidden from constructing the `headers_commission`/`witnessing` payment input type needed to spend that balance.

### Finding Description
Header commissions and witnessing commissions are earned per-address purely based on unit authorship and DAG structure, with no special-casing to exclude AA addresses: [1](#0-0) 
The commission is credited to `address` (the author of the winning child unit) regardless of whether that address is an AA: [2](#0-1) 
An AA response unit is a real unit authored solely by the AA address, produced whenever the AA reacts to a trigger: [3](#0-2) 
Because that response unit is included in the DAG like any other unit, it can be selected as the "best child" of one of its parent units and thereby earn `headers_commission` for the AA address, or (in the witnessing case) an AA address that also happens to be a witness could earn `witnessing` commission — the mechanism in `paid_witnessing.js` likewise credits by plain `address` with no AA exclusion.

However, `validatePaymentInputsAndOutputs` explicitly forbids AA-authored units from using the `headers_commission`/`witnessing` input types needed to actually spend these earned funds: [4](#0-3) 
There is no alternate mechanism in the AA engine (`aa_composer.js`) to move headers_commission_outputs/witnessing_outputs balances into a form the AA can pay out via a normal `payment` message — the AA balance formula used by oscript (`balance[asset]`) and the input-construction code (`inputs.js`) that builds `headers_commission`/`witnessing` inputs are only invoked for ordinary (non-AA) wallets: [5](#0-4) 

This is structurally identical to the AaveStrategy bug: rewards/commissions are automatically and correctly accrued to a fund-holding "contract" address by protocol logic, but the "redeem" (here, spending via the `headers_commission`/`witnessing` input type) is unavailable to that address's execution context (`objValidationState.bAA` blocks it), so the earned bytes are stranded forever.

### Impact Explanation
Any bytes credited to an AA's address as headers commission or witnessing commission become permanently unspendable, both by the AA logic (oscript has no way to build such inputs) and by anyone else (only the address's own definition/authors can spend its outputs, and the AA can only self-author payments through the AA-trigger flow, which is blocked from using these input types). This is a real, protocol-level loss/freezing of funds for any AA address, triggerable simply by the AA processing normal triggers and network DAG growth naturally selecting its response units as best children — no attacker cooperation or special conditions required, only ordinary operation of AAs over time. This satisfies the "AA fund loss or freezing" impact bar.

### Likelihood Explanation
Headers commission winners are selected deterministically from DAG structure (hash-based tie-break) among all children of a parent unit; since every AA response is a broadcast unit that competes normally to be referenced as a parent, and units frequently include many parents, an AA response unit winning header commission for at least one of its parents over the AA's operational lifetime is a routine, expected occurrence — not a rare edge case. Witnessing commission requires the AA address to be a witness, which is less common but not disallowed by the protocol. The headers-commission path alone makes this a likely, naturally-occurring event for high-traffic AAs.

### Recommendation
Either (a) allow AA-authored units to include `headers_commission`/`witnessing` inputs computed deterministically from stored state (so the AA logic, or a system-level auto-sweep, can spend them out in a follow-up response/secondary trigger), or (b) at commission-distribution time (`calcHeadersCommissions`/`updatePaidWitnesses`), detect if the winning address is an AA address and instead credit the earned amount directly into the AA's `aa_balances`/spendable output balance instead of the separate `headers_commission_outputs`/`witnessing_outputs` tables that require the disallowed input type to redeem.

### Proof of Concept
1. Deploy an AA that receives triggers and sends payment responses (any typical AA).
2. Over normal operation, the AA posts many response units, each referencing multiple parent units as normal DAG growth.
3. Per the headers-commission algorithm (`headers_commission.js`), one of these AA response units will, by the deterministic hash-based selection (`getWinnerInfo`), eventually be chosen as the "best child" of one of its parent units, crediting `headers_commission_outputs` to the AA's address (`unit_authors.address` = the AA address).
4. The AA address's balance in `headers_commission_outputs` is now nonzero and `is_spent=0`, but the AA can never construct a unit with `type: "headers_commission"` input because `validatePaymentInputsAndOutputs` rejects it whenever `objValidationState.bAA` is true (`validation.js:2531-2532`). The funds are permanently stuck at the AA address.

### Citations

**File:** headers_commission.js (L30-67)
```javascript
				// headers commissions to single unit author
				conn.query(
					"INSERT INTO headers_commission_contributions (unit, address, amount) \n\
					SELECT punits.unit, address, punits.headers_commission AS hc \n\
					FROM units AS chunits \n\
					JOIN unit_authors USING(unit) \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
					WHERE chunits.is_stable=1 \n\
						AND +chunits.sequence='good' \n\
						AND punits.main_chain_index>? \n\
						AND chunits.main_chain_index-punits.main_chain_index<=1 \n\
						AND +punits.sequence='good' \n\
						AND punits.is_stable=1 \n\
						AND next_mc_units.is_stable=1 \n\
						AND chunits.unit=( "+best_child_sql+" ) \n\
						AND (SELECT COUNT(*) FROM unit_authors WHERE unit=chunits.unit)=1 \n\
						AND (SELECT COUNT(*) FROM earned_headers_commission_recipients WHERE unit=chunits.unit)=0 \n\
					UNION ALL \n\
					SELECT punits.unit, earned_headers_commission_recipients.address, \n\
						ROUND(punits.headers_commission*earned_headers_commission_share/100.0) AS hc \n\
					FROM units AS chunits \n\
					JOIN earned_headers_commission_recipients USING(unit) \n\
					JOIN parenthoods ON chunits.unit=parenthoods.child_unit \n\
					JOIN units AS punits ON parenthoods.parent_unit=punits.unit \n\
					JOIN units AS next_mc_units ON next_mc_units.is_on_main_chain=1 AND next_mc_units.main_chain_index=punits.main_chain_index+1 \n\
					WHERE chunits.is_stable=1 \n\
						AND +chunits.sequence='good' \n\
						AND punits.main_chain_index>? \n\
						AND chunits.main_chain_index-punits.main_chain_index<=1 \n\
						AND +punits.sequence='good' \n\
						AND punits.is_stable=1 \n\
						AND next_mc_units.is_stable=1 \n\
						AND chunits.unit=( "+best_child_sql+" )", 
					[since_mc_index, since_mc_index], 
					function(){ cb(); }
				);
```

**File:** headers_commission.js (L144-187)
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

**File:** validation.js (L2529-2532)
```javascript
				case "headers_commission":
				case "witnessing":
					if (objValidationState.bAA)
						return cb(type+" in AA");
```

**File:** inputs.js (L173-180)
```javascript
	function addHeadersCommissionInputs(){
		addMcInputs("headers_commission", HEADERS_COMMISSION_INPUT_SIZE + (bWithKeys ? HEADERS_COMMISSION_INPUT_KEYS_SIZE : 0),
			headers_commission.getMaxSpendableMciForLastBallMci(last_ball_mci), addWitnessingInputs);
	}

	function addWitnessingInputs(){
		addMcInputs("witnessing", WITNESSING_INPUT_SIZE + (bWithKeys ? WITNESSING_INPUT_KEYS_SIZE : 0), paid_witnessing.getMaxSpendableMciForLastBallMci(last_ball_mci), issueAsset);
	}
```
