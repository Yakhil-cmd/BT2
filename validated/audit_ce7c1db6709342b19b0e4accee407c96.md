### Title
`TokenMappingChangeProposal` Accepts Non-Existent Contract Address at Submission Time, Enabling Post-Vote Malicious Contract Substitution - (File: `x/cronos/types/proposal.go`, `x/cronos/keeper/keeper.go`)

---

### Summary

`TokenMappingChangeProposal.ValidateBasic()` performs only stateless format checks on the `contract` field. It does not verify that the referenced contract address has deployed bytecode on-chain. The on-chain existence check (`ensureContractCode`) only runs at proposal **execution** time inside `RegisterOrUpdateTokenMapping`. This creates a window in which an attacker can submit a governance proposal referencing a not-yet-deployed contract address, obtain community approval, and then deploy a malicious contract at that address (using CREATE2 for deterministic placement) before the proposal is executed. The result is that a malicious CRC20/CRC21 contract becomes the canonical mapping for a denom, corrupting all subsequent IBC/gravity token conversion flows for that denom.

---

### Finding Description

**Submission-time validation gap**

`TokenMappingChangeProposal.ValidateBasic()` checks only:
- Title/description non-empty (`govtypes.ValidateAbstract`)
- Denom format (`IsValidCoinDenom`)
- Contract field is a valid hex address (`common.IsHexAddress`) [1](#0-0) 

No check is made that the address has deployed bytecode. The proposal is accepted by the governance module and enters the deposit/voting period regardless of whether any contract exists at that address.

**Execution-time check is too late**

The actual bytecode check (`ensureContractCode`) only fires inside `RegisterOrUpdateTokenMapping`, which is called by `NewTokenMappingChangeProposalHandler` at execution time — after the voting period has already concluded and the proposal has passed. [2](#0-1) [3](#0-2) [4](#0-3) 

**Deterministic address pre-computation**

EVM CREATE2 allows an attacker to pre-compute the exact address at which a contract will be deployed (`keccak256(0xff || deployer || salt || keccak256(bytecode))`). The attacker can therefore submit a proposal referencing an address that has no code yet, wait for the proposal to pass, and then deploy a malicious contract at that address immediately before the proposal is executed.

---

### Impact Explanation

Once the malicious contract is mapped to a denom (e.g., `gravity0x<token>` or `ibc/<hash>`), it becomes the canonical CRC20/CRC21 contract for all subsequent token conversions on that denom. The malicious contract can include backdoors that allow the attacker to:

- Mint arbitrary token balances for themselves
- Burn or freeze balances of other users
- Transfer tokens without authorization

This directly corrupts the denom/contract binding and IBC/gravity accounting state, matching the **High** impact category: *"Corruption of token mappings, denom/contract binding, IBC channel/accounting state... with direct security impact."* [5](#0-4) 

---

### Likelihood Explanation

The attacker must get a governance proposal passed. This is a meaningful barrier, but it is reachable by an unprivileged actor in two ways:

1. **Sufficient delegated stake**: A large token holder or a coalition can pass a proposal.
2. **Social engineering**: The attacker presents a convincing narrative — e.g., "we are about to deploy the official wrapped-token contract at this pre-computed CREATE2 address" — and voters approve without verifying on-chain existence. The proposal text is the only information voters see; there is no protocol-level enforcement that the contract exists at submission time.

The governance deposit/voting/execution timeline is fully predictable, giving the attacker a deterministic window to deploy the malicious contract between voting end and execution.

---

### Recommendation

Add a stateful contract-existence check at proposal **submission** time. Since `ValidateBasic()` is stateless, the check should be added in the `MsgServer` or `AnteHandler` layer that processes `MsgSubmitProposal`, or alternatively in a `ValidateMsg` hook that has access to the EVM keeper. Concretely:

- In `NewTokenMappingChangeProposalHandler`, call `k.ensureContractCode(ctx, contract)` **before** accepting the proposal into the governance queue, or
- Add a `MsgSubmitProposal` ante-check that, for `TokenMappingChangeProposal` content, calls `HasContractCode` and rejects the submission if the contract does not yet exist.

This mirrors the recommendation in the external report: validate the referenced entity's existence at proposal creation time, not only at execution time. [6](#0-5) 

---

### Proof of Concept

1. Attacker computes `maliciousAddr = CREATE2(attacker, salt, keccak256(maliciousBytecode))` off-chain. No contract is deployed yet.
2. Attacker submits `TokenMappingChangeProposal{Denom: "gravity0x<eth_token>", Contract: maliciousAddr}` with a deposit. `ValidateBasic()` passes (valid hex address, valid denom format). The proposal enters the voting period.
3. Voters inspect the proposal. The contract at `maliciousAddr` has no code; however, the attacker's description claims "the official CRC21 contract will be deployed at this deterministic address." Voters approve.
4. Immediately after the voting period ends (before execution), the attacker calls `CREATE2` and deploys the malicious contract at `maliciousAddr`. The contract contains a backdoor `mint` function callable only by the attacker.
5. The governance module executes the proposal. `RegisterOrUpdateTokenMapping` calls `ensureContractCode(maliciousAddr)` — code now exists, check passes. The mapping `gravity0x<eth_token> → maliciousAddr` is written to state.
6. All subsequent gravity bridge deposits of `<eth_token>` are converted into the malicious CRC20. The attacker calls the backdoor to mint tokens to themselves, draining the equivalent native denom supply. [1](#0-0) [7](#0-6)

### Citations

**File:** x/cronos/types/proposal.go (L44-66)
```go
// ValidateBasic validates the parameter change proposal
func (tcp *TokenMappingChangeProposal) ValidateBasic() error {
	if err := govtypes.ValidateAbstract(tcp); err != nil {
		return err
	}

	if !IsValidCoinDenom(tcp.Denom) {
		return fmt.Errorf("invalid coin denom: %s", tcp.Denom)
	}

	if IsSourceCoin(tcp.Denom) {
		// source-denom mappings always require a valid contract address
		if !common.IsHexAddress(tcp.Contract) {
			return fmt.Errorf("invalid contract address for source denom: %s", tcp.Contract)
		}
	} else {
		// non-source mappings allow empty contract (delete) or a valid hex address
		if len(tcp.Contract) > 0 && !common.IsHexAddress(tcp.Contract) {
			return fmt.Errorf("invalid contract address: %s", tcp.Contract)
		}
	}

	return nil
```

**File:** x/cronos/keeper/keeper.go (L308-310)
```go
func (k Keeper) HasContractCode(ctx sdk.Context, contract common.Address) bool {
	return k.ensureContractCode(ctx, contract) == nil
}
```

**File:** x/cronos/keeper/keeper.go (L312-327)
```go
func (k Keeper) ensureContractCode(ctx sdk.Context, contract common.Address) error {
	if contract.Big().Cmp(big.NewInt(256)) < 0 {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress,
			"crc21 contract must not be in precompile range: %s", contract.Hex())
	}
	resp, err := k.evmKeeper.Code(ctx, &evmtypes.QueryCodeRequest{
		Address: contract.Hex(),
	})
	if err != nil {
		return errors.Wrapf(sdkerrors.ErrInvalidAddress, "failed to query contract code (%s): %v", contract.Hex(), err)
	}
	if resp == nil || len(resp.Code) == 0 {
		return errors.Wrapf(sdkerrors.ErrInvalidRequest, "no contract code at address (%s)", contract.Hex())
	}
	return nil
}
```

**File:** x/cronos/keeper/keeper.go (L329-404)
```go
// RegisterOrUpdateTokenMapping update the token mapping, register a coin metadata if needed
func (k Keeper) RegisterOrUpdateTokenMapping(ctx sdk.Context, msg *types.MsgUpdateTokenMapping) error {
	if types.IsSourceCoin(msg.Denom) {
		_, err := types.GetContractAddressFromDenom(msg.Denom)
		if err != nil {
			return err
		}

		if !common.IsHexAddress(msg.Contract) {
			return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address (%s)", msg.Contract)
		}
		contract := common.HexToAddress(msg.Contract)
		if err := k.ensureContractCode(ctx, contract); err != nil {
			return err
		}
		if err := validateContractAddressForSourceDenom(msg.Denom, contract, true); err != nil {
			return err
		}

		if err := k.SetExternalContractForDenom(ctx, msg.Denom, contract); err != nil {
			return err
		}

		// check that the coin is registered, otherwise register it
		metadata, exist := k.bankKeeper.GetDenomMetaData(ctx, msg.Denom)
		if !exist {
			// create new metadata
			metadata = banktypes.Metadata{
				Base: msg.Denom,
				Name: msg.Denom,
			}
		}
		// update existing metadata
		metadata.Symbol = msg.Symbol
		metadata.Display = strings.ToLower(msg.Symbol)
		if msg.Decimal != 0 {
			metadata.DenomUnits = []*banktypes.DenomUnit{
				{
					Denom:    metadata.Base,
					Exponent: 0,
				},
				{
					Denom:    metadata.Display,
					Exponent: msg.Decimal,
				},
			}
		} else {
			metadata.DenomUnits = []*banktypes.DenomUnit{
				{
					Denom:    metadata.Base,
					Exponent: 0,
				},
			}
		}
		k.bankKeeper.SetDenomMetaData(ctx, metadata)
	} else {
		if len(msg.Contract) == 0 {
			// delete existing mapping
			k.DeleteExternalContractForDenom(ctx, msg.Denom)
		} else {
			if !common.IsHexAddress(msg.Contract) {
				return errors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid contract address (%s)", msg.Contract)
			}
			// update the mapping
			contract := common.HexToAddress(msg.Contract)
			if err := k.ensureContractCode(ctx, contract); err != nil {
				return err
			}
			if err := k.SetExternalContractForDenom(ctx, msg.Denom, contract); err != nil {
				return err
			}
		}
	}

	return nil
}
```

**File:** x/cronos/proposal_handler.go (L15-33)
```go
func NewTokenMappingChangeProposalHandler(k keeper.Keeper) govtypes.Handler {
	return func(ctx sdk.Context, content govtypes.Content) error {
		switch c := content.(type) {
		case *types.TokenMappingChangeProposal:
			if err := c.ValidateBasic(); err != nil {
				return err
			}

			msg := types.MsgUpdateTokenMapping{
				Denom:    c.Denom,
				Contract: c.Contract,
				Symbol:   c.Symbol,
				Decimal:  c.Decimal,
			}
			return k.RegisterOrUpdateTokenMapping(ctx, &msg)
		default:
			return errors.Wrapf(sdkerrors.ErrUnknownRequest, "unrecognized cronos proposal content type: %T", c)
		}
	}
```
