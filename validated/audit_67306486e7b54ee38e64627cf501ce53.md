### Title
Autonomous Agent addresses can be assigned headers/witnessing commissions but can never spend them, permanently freezing funds - ([File: validation.js])

### Summary
Obyte allows a unit author to redirect part of the headers commission it earns to another address via the `earned_headers_commission_recipients` message, which can name any address, including an Autonomous Agent (AA) address. Headers commissions and witnessing (payload) commissions credited to an address are only spendable through special `headers_commission`/`witnessing` input types. Validation of payment inputs explicitly forbids these input types when the payer/spender is an AA, so any commission credited to an AA address can never be claimed by that AA, permanently freezing the funds — the same root-cause pattern as the referenced AAVE report, where an account structurally lacks a code path to claim value that has already accrued to it.

### Finding Description
Headers commissions are distributed to "author of child unit or address named in `earned_headers_commission_recipients`" [1](#0-0) , and this redistribution mechanism accepts an arbitrary destination `address` supplied in the unit's `earned_headers_commission_recipients` message [2](#0-1) . These credited amounts are persisted per-address in `headers_commission_outputs` / `witnessing_outputs` and can only be turned into spendable balance by constructing a payment message whose `inputs` array contains an input of `type: "headers_commission"` or `type: "witnessing"` [3](#0-2) .

However, `validatePaymentInputsAndOutputs` explicitly rejects these input types whenever the spending unit belongs to an AA:
```
case "headers_commission":
case "witnessing":
    if (objValidationState.bAA)
        return cb(type+" in AA");
``` [4](#0-3) 

Since an AA can never post a unit containing a `headers_commission`/`witnessing` input (the check unconditionally rejects it for `objValidationState.bAA`), any commission balance that accumulates under an AA address in `headers_commission_outputs` or `witnessing_outputs` is permanently unspendable by that AA. There is no other code path (bounce, AA response logic, or otherwise) that lets an AA construct such an input, mirroring the reported AAVE issue where `BaseIncentivesController.claimRewards()` exists but the margin-account contract has no way to invoke it.

### Impact Explanation
Funds legitimately owed to an address (commission earnings, analogous to the AAVE reward tokens) become permanently frozen and unrecoverable once credited to an AA address, because the protocol categorically forbids AAs from using the only input type capable of spending them. This is a concrete, permanent AA fund freezing/loss, matching the accepted impact category of "AA fund loss or freezing."

### Likelihood Explanation
Any regular unit author can trivially trigger this by including an `earned_headers_commission_recipients` message naming an AA address as a commission recipient (a normal, permitted operation for redistributing headers commission), or by an AA address being included in a witness list arrangement that yields witnessing outputs. No special privilege beyond posting an ordinary unit is required, and the resulting frozen balance is a direct, deterministic consequence of the `bAA` check in validation, not a probabilistic or attacker-adversarial condition.

### Recommendation
Either (a) forbid AA addresses from being named as `earned_headers_commission_recipients` / from being credited `headers_commission_outputs`/`witnessing_outputs` at the point these are assigned (validate the recipient address is not an AA address before insertion, in `headers_commission.js`/`paid_witnessing.js` and the message-validation for `earned_headers_commission_recipients`), or (b) provide an AA-specific path to claim these balances (e.g., allow bounce/response logic to redeem accrued headers/witnessing commissions into the AA's regular spendable balance).

### Proof of Concept
1. Author unit `U1` includes an `earned_headers_commission_recipients` message naming `AA_ADDR` (a valid AA address) as a 100% commission recipient, per the mechanism in [2](#0-1) .
2. Once `U1` wins headers commission on stabilization, `headers_commission_outputs` credits `amount` to `AA_ADDR` [5](#0-4) .
3. Attempt to spend this balance requires constructing a unit authored effectively by `AA_ADDR` with an input `{type: "headers_commission", from_main_chain_index, to_main_chain_index}`.
4. Validation rejects it unconditionally because `objValidationState.bAA` is true for the AA: `return cb(type+" in AA")` [6](#0-5) .
5. The credited commission amount at `AA_ADDR` can never be spent — permanently frozen.

### Citations

**File:** headers_commission.js (L30-33)
```javascript
				// headers commissions to single unit author
				conn.query(
					"INSERT INTO headers_commission_contributions (unit, address, amount) \n\
					SELECT punits.unit, address, punits.headers_commission AS hc \n\
```

**File:** headers_commission.js (L144-152)
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

**File:** validation.js (L2529-2532)
```javascript
				case "headers_commission":
				case "witnessing":
					if (objValidationState.bAA)
						return cb(type+" in AA");
```

**File:** initial-db/byteball-sqlite.sql (L353-360)
```sql
CREATE TABLE headers_commission_outputs (
	main_chain_index INT NOT NULL, -- mci of the sponsoring (paying) unit
	address CHAR(32) NOT NULL, -- address of the commission receiver
	amount BIGINT NOT NULL,
	is_spent TINYINT NOT NULL DEFAULT 0,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (main_chain_index, address)
);
```
