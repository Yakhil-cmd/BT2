### Title
Cross-repository Commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook by binding the HMAC check to the **organization** implied by the payload (`repository.owner.login` or `organization.login`), then dispatches the raw JSON to the relevant `Shipit::Webhooks::Handlers` class [1](#0-0) [2](#0-1) . Every other event handler re-derives the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` through the shared `stacks` helper, so the entity that authenticated the request is bound to the entity being written [3](#0-2) . `StatusHandler`, however, breaks this binding: it never consults `repository`/`stacks` at all and instead resolves target rows with a **global, unscoped** `Commit.where(sha: params.sha)` lookup [4](#0-3) .

### Finding Description
The binding that should hold is:
`organization authenticated by verify_signature == organization owning the Commit rows mutated by the handler`

Before the attacker's action: a `status` webhook signed with organization A's `webhook_secret` can only be legitimately produced by GitHub for events on organization A's own repositories, so `repository_owner` used for signature verification and the commit that generated the event are the same organization.

After: `StatusHandler#process` ignores the verified `repository`/`organization` context entirely and matches on `sha` alone, then calls `commit.create_status_from_github!(params)` on every `Commit` row across the whole install that shares that SHA [4](#0-3) . Because SHA-1 commit ids are content-addressed, identical commits are extremely common across the fleet of stacks Shipit typically manages for one codebase (e.g. the same repository deployed under different `Stack`s/branches/environments, or forks/mirrors tracked as separate `Repository` records). An attacker who legitimately controls (or has push access to) any one organization/repository with the Shipit GitHub App installed can trigger a genuinely GitHub-signed `status` event — signed with *their own org's* `webhook_secret` — carrying an arbitrary `state`/`description`/`target_url`/`context` for a `sha` value that also exists as a `Commit` in a different organization's tracked `Stack`.

This is the direct structural analog of the Taiko bug class named in the rules: a value the code trusts as "authorized" (`repository_owner`, which the HMAC check is keyed on) is not actually the value the mutating code operates on (`Commit.where(sha:)`, unscoped to any repository/organization). Compare with `CheckSuiteHandler` and `PushHandler`, which correctly scope their writes through `stacks` (derived from the verified `repository.full_name`) [5](#0-4) [6](#0-5) ; `StatusHandler` alone omits this scoping.

### Impact Explanation
Commit statuses control merge and deploy readiness gating throughout the engine (see `Commit#create_status_from_github!` and status-based merge checks). An attacker with legitimate write access to one org/repo tracked by any Shipit deployment can forge a `success` status on an identical-SHA commit belonging to a completely different, unrelated organization's stack, potentially unblocking a deploy or merge gate that depends on required status checks for that commit in the victim organization — without any credential, GitHub token, or write access to the victim repository. This is a cross-repository write achieved purely by exploiting the missing binding between the authenticating organization and the repository actually mutated.

### Likelihood Explanation
Exploitability requires two genuinely commodity conditions: (1) the attacker has ordinary push/webhook-triggering rights on *any* GitHub org/repo where the Shipit GitHub App is installed (a routine, unprivileged position for many users of a shared Shipit instance), and (2) a commit SHA collision with a target stack, which is common when the same upstream commit is deployed as multiple `Stack`s (staging/production, multiple regions, forks) — a very typical Shipit usage pattern. No secrets, tokens, or victim-repo access are required.

### Recommendation
Scope `StatusHandler#process` the same way as the other handlers: resolve the target `Stack`/`Repository` via `payload.dig('repository', 'full_name')` (the `stacks` helper already used by `Handler`), and only update/query `Commit` rows that belong to that repository's stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Attacker has push access to `attacker-org/repo-x`, which has the Shipit GitHub App installed with its own `webhook_secret`.
2. Attacker (or CI in their repo) pushes a commit whose tree/content is identical to a commit already tracked by `victim-org/repo-y`'s `Stack` (same SHA), or otherwise arranges for a SHA collision with a target commit (e.g. cherry-picking/rebasing a known upstream commit that is also deployed by the victim stack).
3. GitHub sends a `status` webhook for `attacker-org/repo-x`, correctly signed with `attacker-org`'s `webhook_secret`; `verify_signature` passes because it only checks the signature against `repository_owner` = `attacker-org` [1](#0-0) .
4. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which runs `Commit.where(sha: params.sha)` [4](#0-3)  and updates the status of the matching `Commit` row belonging to `victim-org/repo-y`'s stack, even though the signature only proved the request came from `attacker-org`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-16)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
