### Title
Unvalidated `governance.govparamcontract` Vote Allows Arbitrary Contract to Override Reward Parameters — (`kaiax/gov/headergov/impl/header.go`, `kaiax/gov/contractgov/impl/getter.go`)

---

### Summary

In `none` governance mode (or pre-Permissionless `single` mode), any council member can cast a governance vote to set `governance.govparamcontract` to an arbitrary address. The `checkConsistency` function performs no validation on this address beyond format-checking it as a valid Ethereum address. Once ratified, the `contractgov` module blindly calls `getAllParamsAt()` on that address and uses the returned values to override all header-governance parameters (post-Kore). A malicious contract at that address can return arbitrary values for `reward.mintingamount`, `reward.ratio`, `reward.kip82ratio`, etc., causing unauthorized minting of KAIA or unauthorized redistribution of block rewards.

---

### Finding Description

**Root cause — no allowlist or contract-validity check on `GovernanceGovParamContract` votes:**

In `checkConsistency` (`kaiax/gov/headergov/impl/header.go`), the `GovernanceGovParamContract` case is grouped with parameters that unconditionally return `nil`:

```go
case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
    ...
    return nil
```

The test file explicitly acknowledges this gap:

```go
// govparamcontract is not state-checked here; a non-contract address is accepted
{desc: "govparam not state-checked", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceGovParamContract), eoa), expectedError: nil},
```

Any syntactically valid Ethereum address — including an EOA or a malicious contract — passes vote validation.

**Trigger path — `none` mode or pre-Permissionless `single` mode:**

In `governance_vote` (`kaiax/gov/headergov/impl/api.go`):

```go
if gMode == "single" && voter != gp.GoverningNode {
    return "", ErrVotePermissionDenied
}
```

In `none` mode this check is skipped entirely, so any council member can vote. In `VerifyVote` (`kaiax/gov/headergov/impl/header.go`), the single-mode restriction is only enforced post-Permissionless fork:

```go
if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
```

On pre-Permissionless `single`-mode chains, any council member who becomes a block proposer can embed the malicious vote in `header.Vote`.

The default value for `governance.governancemode` is `"none"` (`kaiax/gov/param.go` line 229), making this the default attack surface for any chain that does not explicitly configure `single` mode.

**Exploitation — malicious contract overrides reward parameters:**

After the vote is ratified at the next epoch block, `contractAddrAt` returns the attacker-controlled address:

```go
func (c *contractGovModule) contractAddrAt(blockNum uint64) (common.Address, error) {
    headerParams := c.Hgm.GetParamSet(blockNum)
    return headerParams.GovParamContract, nil
}
```

`contractGetAllParamsAtFromAddr` then calls `getAllParamsAt()` on that address with no further validation:

```go
contract, err := govcontract.NewGovParamCaller(addr, caller)
...
names, values, err := contract.GetAllParamsAt(nil, new(big.Int).SetUint64(blockNum))
```

The returned parameters are merged into the effective `ParamSet` with the highest precedence (post-Kore), overriding header governance:

```go
// kaiax/gov/impl/getter.go
if m.isKoreHF(blockNum) {
    p2 := m.Cgm.GetPartialParamSet(blockNum)
    for k, v := range p2 {
        err := ret.Set(k, v)
```

A malicious contract returning `reward.mintingamount = "999999999999999999999999999999"` passes the only validation (big.Int canonicalization) and is accepted. The `reward` module then mints that amount every block via `FinalizeState`.

---

### Impact Explanation

- **Unauthorized minting of KAIA**: A malicious `GovParamContract` can return an arbitrarily large `reward.mintingamount`. Every block after ratification, `FinalizeState` mints that amount and distributes it to validators and fund addresses, inflating the total supply without authorization.
- **Unauthorized reward redistribution**: Returning `reward.ratio = "100/0/0"` redirects all block rewards to validators, starving KIF/KEF/KPF funds.
- **Governance takeover**: Returning `governance.governingnode = <attacker>` (if not deprecated at that fork) transfers single-mode governance authority to the attacker.

All of these are direct, on-chain state changes affecting KAIA balances and system-managed funds.

---

### Likelihood Explanation

- **`none` mode** is the default governance mode (`DefaultValue: "none"` in `kaiax/gov/param.go`). Any council member on a `none`-mode chain who becomes a block proposer within an epoch can embed the malicious vote. The last vote in the epoch wins, so a council member who proposes a block near the epoch boundary can override earlier legitimate votes.
- **Pre-Permissionless `single` mode**: Any council member who becomes a proposer can embed the vote before the Permissionless fork activates the governing-node restriction.
- The attack requires only a single council member (semi-trusted validator), not majority collusion.
- The epoch delay (e.g., 604,800 blocks on Mainnet) provides a detection window, but the ratification is deterministic once the vote is embedded.

---

### Recommendation

1. **Add an allowlist of permitted `GovParamContract` addresses** in `checkConsistency`, analogous to the fix in the referenced OptimismGovernor commit. Reject votes for addresses not on the allowlist.
2. **Alternatively, validate that the voted address contains deployed contract code** at the time of the vote (call `chain.GetCode(addr, blockNum)` and reject if empty).
3. **Add a range check on `reward.mintingamount`** returned by contract governance (e.g., cap it at the current header-governance value multiplied by a safety factor) so that even if a malicious contract is used, the damage is bounded.
4. **Enforce the allowlist check in `contractGetAllParamsAtFromAddr`** as a defense-in-depth measure, verifying the address matches the known-good `GovParamContract` before trusting its output.

---

### Proof of Concept

**Setup**: A Kaia network running in `none` governance mode (default), post-Kore fork.

**Step 1 — Deploy malicious GovParam contract:**
```solidity
contract MaliciousGovParam {
    function getAllParamsAt(uint256) external pure
        returns (string[] memory names, bytes[][] memory values)
    {
        names = new string[](1);
        names[0] = "reward.mintingamount";
        values = new bytes[][](1);
        values[0] = new bytes[](1);
        // Encode 10^36 wei (10^18 KAIA) as big-endian bytes
        values[0][0] = abi.encodePacked(uint256(10**36));
    }
}
```

**Step 2 — Cast the vote:**
Any council member calls `governance_vote("governance.govparamcontract", "<malicious_addr>")` via the JSON-RPC API. The vote is embedded in `header.Vote` when that node proposes a block.

**Step 3 — Ratification:**
At the next epoch block, the proposer calls `getExpectedGovernance()`, which collects the last vote for `governance.govparamcontract` and writes it to `header.Governance`. All nodes accept this via `VerifyGov` (which only checks that the governance matches the locally computed expected value — it does not validate the address).

**Step 4 — Exploitation:**
Starting from `(k+1)*epoch`, `contractAddrAt` returns the malicious address. Every block, `contractGetAllParamsAtFromAddr` calls `getAllParamsAt()` on the malicious contract, receives `reward.mintingamount = 10^36`, and `FinalizeState` mints `10^36` wei to the proposer and fund addresses each block.

**Corrupted value**: `ParamSet.MintingAmount` is set to `10^36` wei instead of the legitimate `9.6e18` wei, causing `10^17`× over-minting of KAIA per block. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L101-107)
```go
	// In single mode, only the governing node can write header.Vote after Permissionless.
	params := h.GetParamSet(blockNum)
	if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
		params.GovernanceMode == "single" &&
		vote.Voter() != params.GoverningNode {
		return ErrVotePermissionDenied
	}
```

**File:** kaiax/gov/headergov/impl/header.go (L156-215)
```go
// checkConsistency checks if vote values are consistent with chain states such as other parameters and validator set.
func (h *headerGovModule) checkConsistency(blockNum uint64, vote headergov.VoteData) error {
	switch vote.Name() {
	case gov.GovernanceGoverningNode:
		params := h.GetParamSet(blockNum)

		// compare with governing node only in single mode.
		if params.GovernanceMode != "single" {
			return nil
		}

		// we'll use blockNum-1 for the blocknumber of GetCouncil since blockNum cannot be available(eg. vote)
		// it's definite that the valSet vote is not included in this block
		// so the council(blockNum - 1) and council(blockNum) should be same
		council, err := h.ValSet.GetCouncil(blockNum - 1)
		if err != nil {
			return err
		}

		if slices.Contains(council, params.GoverningNode) {
			return nil
		}
		return ErrGovNodeNotInValSetList
	case gov.Kip71LowerBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) > params.UpperBoundBaseFee {
			return ErrLowerBoundBaseFee
		} else {
			return nil
		}
	case gov.Kip71UpperBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) < params.LowerBoundBaseFee {
			return ErrUpperBoundBaseFee
		} else {
			return nil
		}
	case gov.AddValidator, gov.RemoveValidator:
		params := h.GetParamSet(blockNum)

		// compare with governing node only in single mode.
		if params.GovernanceMode != "single" {
			return nil
		}
		if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
			return ErrGovNodeInValSetVoteValue
		}
		return nil
		// These votes are valid as long as it passes the format checks in NewVoteData(). No more checks here.
	case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
		gov.IstanbulCommitteeSize, gov.IstanbulEpoch, gov.IstanbulPolicy,
		gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
		gov.RewardDeferredTxFee, gov.RewardKip82Ratio, gov.RewardMintingAmount, gov.RewardMinimumStake,
		gov.RewardProposerUpdateInterval, gov.RewardRatio, gov.RewardStakingRewardThreshold,
		gov.RewardStakingUpdateInterval, gov.RewardUseFlexReward, gov.RewardUseGiniCoeff:
		return nil
	default:
		return ErrInvalidKeyValue
	}
}
```

**File:** kaiax/gov/contractgov/impl/getter.go (L55-93)
```go
func (c *contractGovModule) contractGetAllParamsAtFromAddr(blockNum uint64, addr common.Address) (gov.PartialParamSet, error) {
	chain := c.Chain
	if chain == nil {
		return nil, ErrNotReady
	}

	config := c.ChainConfig
	if !config.IsKoreForkEnabled(new(big.Int).SetUint64(blockNum)) {
		return nil, ErrNotReady
	}

	caller := backends.NewBlockchainContractBackend(chain, nil, nil)
	contract, err := govcontract.NewGovParamCaller(addr, caller)
	if err != nil {
		return nil, err
	}

	names, values, err := contract.GetAllParamsAt(nil, new(big.Int).SetUint64(blockNum))
	if err != nil {
		logger.Warn("ContractEngine disabled: getAllParams call failed", "err", err)
		return nil, nil
	}

	if len(names) != len(values) {
		logger.Warn("ContractEngine disabled: getAllParams result invalid", "len(names)", len(names), "len(values)", len(values))
		return nil, nil
	}

	ret := ParseContractCall(names, values)

	rules := config.Rules(new(big.Int).SetUint64(blockNum))
	for name := range ret {
		if gov.DeprecatedAt(name, rules) {
			logger.Warn("Ignoring deprecated parameter from contract governance", "name", name, "blockNum", blockNum)
			delete(ret, name)
		}
	}

	return ret, nil
```

**File:** kaiax/gov/contractgov/impl/getter.go (L96-99)
```go
func (c *contractGovModule) contractAddrAt(blockNum uint64) (common.Address, error) {
	headerParams := c.Hgm.GetParamSet(blockNum)
	return headerParams.GovParamContract, nil
}
```

**File:** kaiax/gov/impl/getter.go (L26-34)
```go
	if m.isKoreHF(blockNum) {
		p2 := m.Cgm.GetPartialParamSet(blockNum)
		for k, v := range p2 {
			err := ret.Set(k, v)
			if err != nil {
				logger.CritWithStack("Failed to add param from ContractGov", "name", k, "value", v, "error", err)
			}
		}
	}
```

**File:** kaiax/gov/headergov/impl/api.go (L53-63)
```go
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
	var (
		voter     = api.h.nodeAddress
		nextBlock = api.h.Chain.CurrentBlock().NumberU64() + 1
		gp        = api.h.GetParamSet(nextBlock)
		gMode     = gp.GovernanceMode
	)

	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}
```

**File:** kaiax/gov/headergov/impl/header_test.go (L82-85)
```go
		{desc: "valid govparam", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceGovParamContract), contract), expectedError: nil},
		{desc: "valid unitprice", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceUnitPrice), uint64(25000000000)), expectedError: nil},
		// govparamcontract is not state-checked here; a non-contract address is accepted (verified via committed seals).
		{desc: "govparam not state-checked", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceGovParamContract), eoa), expectedError: nil},
```

**File:** kaiax/gov/param.go (L226-230)
```go
			}
			return c.Governance.GovernanceMode, nil
		},
		DefaultValue: "none",
	},
```
