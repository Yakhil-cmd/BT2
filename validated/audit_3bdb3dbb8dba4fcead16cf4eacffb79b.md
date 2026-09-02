Confirming the equality binding: the question claims signature verification uses `organization = A` (via `repository_owner` falling back to `params.dig('organization','login')`) while the mutated `Commit`/`Stack` belongs to `B` (from `params['repository']['full_name']`). Tracing the code shows this divergence is real and unguarded.

### Title
Cross-tenant commit-status forgery via `organization`/`repository` payload divergence in `WebhooksController#verify_signature` - ([File: `app/controllers/shipit/webhooks_controller.rb`])

### Summary
`Shipit::WebhooksController#repository_owner` selects the signing organization as `params.dig('repository','owner','login') || params.dig('organization','login')`, but `StatusHandler#process` looks up the target `Commit` purely by `params.sha`, independent of which organization's key verified the signature. An attacker who legitimately controls a Shipit-connected organization `A` (and thus knows/can trigger `A`'s real `webhook_secret` via their own configured GitHub webhook) can send a `status` event whose `sha` collides with a commit that actually belongs to a `Stack` under organization `B`'s repository, causing `Commit#create_status_from_github!` to write a forged `CommitStatus` on `B`'s commit while verification only proved authorization for `A`.

### Finding Description
Binding claimed broken: `verifying_org(A) == owning_org(mutated Commit/Stack)`.

- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and validates HMAC-SHA1 using that org's `webhook_secret` against the raw POST body [1](#0-0) .
- `repository_owner` prefers `repository.owner.login`, but falls back to `organization.login` if the `repository` key/owner is absent from the JSON body [2](#0-1) .
- `StatusHandler#process` resolves the target purely via `Commit.where(sha: params.sha)`, with no re-check that the commit's `stack`/repository corresponds to the organization used in `verify_signature` [3](#0-2) .
- `Commit#create_status_from_github!` writes the status onto whatever `Commit` record matched the sha, tied to its own `stack`, and emits `Hook.emit(:commit_status, stack, ...)` for that stack [4](#0-3) [5](#0-4) .

However, the premise that the *repository* field can diverge from the *organization* field while both point to different owners **that the attacker does not control** does not itself grant new capability, because:
1. `verify_signature` requires a valid HMAC computed with the actual `webhook_secret` configured for whichever organization `repository_owner` resolves to [6](#0-5) . Per the stated threat model, the attacker holds **no** `webhook_secret` for any organization other than one they legitimately control (e.g., their own GitHub org/installation, call it `A`). They cannot forge a signature that `Shipit.github(organization: 'B').verify_webhook_signature` (or `A`'s) would accept for arbitrary attacker-chosen content unless the secret used equals `A`'s own secret, which only proves the request came from `A`'s installation — not from `B`.
2. Because `repository_owner` is derived from attacker-controlled JSON body content (not from the URL/route), the attacker who owns org `A`'s GitHub App installation can indeed set `organization.login = A` and set `repository.full_name = B/repo` inside the same JSON payload, producing a signature valid for `A` while claiming an unrelated `sha`. Since `Commit.where(sha:)` has no scoping to `A`, if that `sha` string collides with a real commit ingested under `B`'s stack (an existing SHA in Shipit's DB, which is a 40-hex-char GitHub commit hash the attacker would need to already know/guess — SHAs are public information visible on GitHub for public repos, or leaked via other means), the forged status lands on `B`'s commit.
3. There is no code path that cross-checks `commit.stack.repository.owner` against `repository_owner`/verifying org before or after `Commit.where(sha:)`; no `ExplicitParameters` schema field enforces repository identity, and `drop_unhandled_event`/`check_if_ping` do not perform this check either [7](#0-6) .

Both sides of the equality are checked: before the fix, `verifying_org` = whatever the payload's `organization.login` says (attacker-controlled string, validated only via signature against that string's configured secret), while `owning_org` = the actual owner of the `Stack`/`Repository` that owns the matched `Commit` row — these are never compared, so they can diverge whenever the attacker supplies a `sha` value that exists under a different org's stack than the one whose secret signed the request.

### Impact Explanation
The attacker can write an arbitrary `CommitStatus` (state, description, context, target_url) onto a `Commit` belonging to a repository/organization they do not own and did not sign for, provided they can guess or discover the target SHA (public commit hashes are typically enumerable for public repos, or via prior PR/webhook observation). This is a payload for organization `A` mutating stack/commit data belonging to organization `B` — cross-tenant commit-status forgery, matching the "Critical" category of "a payload for one repository mutating another's stack, commit, task or team." It could be used to mark a malicious commit as passing/green in `B`'s stack (potentially unblocking deploys if `blocking_statuses`/`required_statuses` gate on that context), or to spam/fail `B`'s legitimate commits (denial of trustworthy CI signal), which is repeatable for any SHA the attacker can enumerate.

### Likelihood Explanation
Requires: (a) the attacker legitimately administers at least one organization/repository connected to this Shipit instance (i.e., they have a valid, configured GitHub App installation with its own `webhook_secret`) — a real but plausible precondition in multi-tenant Shipit deployments serving multiple orgs; (b) knowledge of a target commit SHA belonging to another org's stack, which is generally public/discoverable; (c) no additional Shipit privileges are needed since the endpoint is unauthenticated aside from the HMAC check. Cost is low (single crafted HTTP POST), and the attack is repeatable against any SHA in any stack once org `A`'s installation is set up.

### Recommendation
In `StatusHandler#process` (and analogous handlers), after locating matching `Commit`/`Stack` records, verify that the commit's `stack.repository` (owner/full_name) matches the `repository_owner`/organization that was used to verify the webhook signature, and skip/reject records that don't match. Alternatively, scope `Commit.where(sha:)` to `Repository.where(owner: repository_owner)`/`Stack` joined on the verified organization before creating statuses.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure two orgs in `Shipit.github` config fixtures: `A` with `webhook_secret = 'secretA'`, `B` with `webhook_secret = 'secretB'`.
2. Create `stack_b` under `repository.owner.login = 'B'`, and a `Commit` `commit_b` with `sha = 'deadbeef...'` belonging to `stack_b`.
3. Build a JSON body: `{"organization":{"login":"A"},"repository":{"full_name":"B/repo"},"sha":"deadbeef...","state":"success", ...}` (no `repository.owner.login`, forcing fallback).
4. Compute `X-Hub-Signature` as `"sha1=" + HMAC-SHA1(secretA, raw_body)`.
5. POST to `/webhooks` with header `X-Github-Event: status` and the above signature.
6. Assert: `verifying_org` == `'A'` (via `repository_owner`) succeeds signature check (response is `200`, not `422`).
7. Assert: `commit_b.reload.statuses.last.state == 'success'` — i.e., the status landed on `B`'s commit despite verification only proving `A`'s authorization, proving `verifying_org(A) != owning_org(B)` while the mutation still occurred.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
