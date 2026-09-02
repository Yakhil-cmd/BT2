### Title
`StatusHandler` applies commit statuses without checking that the commit belongs to the webhook's claimed repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Every other webhook handler in this engine scopes its writes through `Handler#stacks`, which resolves the target `Stack` via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` [1](#0-0) . `StatusHandler`, however, never calls `stacks`/`repository_name` at all — it looks up commits globally by SHA and writes a status to every match: [2](#0-1) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/secret to validate the HMAC against using only `repository_owner` (`repository.owner.login` or `organization.login`) taken from the payload [3](#0-2) . That check only proves "this payload was signed by *some* GitHub organization configured in this Shipit instance" — it says nothing about which repository's commits the payload is allowed to affect. The `repository.full_name` field, which every other handler uses to scope writes to the correct `Stack`, is part of the JSON body and is itself covered by the same HMAC, but `StatusHandler#process` simply never reads it. Instead it does a bare `Commit.where(sha: params.sha)`, which is a global, cross-stack, cross-repository query [4](#0-3) .

Git commit SHAs are content-addressed and are frequently shared across repositories with common history (forks, mirrors, subtree merges). Any commit that is reachable in two Shipit-tracked stacks — most commonly a fork/upstream pair, both onboarded as separate Shipit `Stack`s — will have the identical `sha`. A validly signed "status" webhook for repo A (whose SHA happens to also exist as a commit in repo B's `Stack`) will cause `Commit.where(sha:)` to match the row belonging to repo B and call `create_status_from_github!` on it, mutating that commit's status regardless of the value of `payload['repository']['full_name']`.

This is the "organization/repository named in the payload versus the repository actually written" binding from the report's bug class: `adminSettleDebt()` trusted stale/wrong internal state because it lacked a scope/guard check; here, `StatusHandler` trusts a SHA lookup with no scope/guard tying it to the repository the signature context implies.

`commit.create_status_from_github!` ultimately drives `Commit#add_status`, which can trigger `stack.schedule_merges` when the new status is `pending`/`success` [5](#0-4) , and updates the commit's deployability, which the merge queue and deploy UI treat as an authoritative CI signal for that stack.

### Impact Explanation
An attacker who can trigger a legitimately signed "status" webhook for a repository they control (e.g., a fork tracked as its own Shipit stack) can forge a `success`/`failure` commit status on a commit belonging to a *different* tracked stack, as long as that commit's SHA is shared history. Because `Commit#add_status` can call `stack.schedule_merges` on success statuses, this can push an unrelated stack's commit toward being treated as deployable/mergeable — an unauthorized-deploy-adjacent state change on a repository the attacker has no write access to. This satisfies the "unauthorized deploy" impact bucket without requiring any secret, token, or privileged account: the attacker only needs a fork of the target repository tracked by the same Shipit instance and the ability to post statuses to their own fork through normal GitHub flows (e.g., their own CI on the fork).

### Likelihood Explanation
Low-to-moderate. It requires: (1) the same Shipit instance tracking both the victim stack and an attacker-controlled fork/mirror sharing commit history, and (2) a shared commit SHA still being un-deployed/pending in the victim stack at the time the forged status lands. This is a natural occurrence for organizations that track both upstream and fork stacks (a supported configuration, evidenced by the multi-org secrets fixture [6](#0-5) ), but is not universally exploitable against arbitrary unrelated repositories.

### Recommendation
Scope `StatusHandler#process` the same way every other handler is scoped: resolve the target stacks via `repository_name`/`stacks` (as defined in `Handler#stacks`) and constrain the `Commit.where(sha:)` lookup to `stacks.commits` (or equivalently, join through `stack_id` derived from the payload's `repository.full_name`) instead of querying `Commit` globally.

### Proof of Concept
1. Shipit instance tracks `Stack A` = `victim-org/app` and `Stack B` = `attacker/app` (a fork of `victim-org/app`), both with valid GitHub App/webhook configuration.
2. Both stacks share commit `abc123...` (pre-fork history).
3. Attacker triggers a GitHub `status` event on their own fork for SHA `abc123...` with `state: success` (e.g., via their own CI/GitHub Actions run on the fork, which they fully control).
4. GitHub signs and delivers the webhook using the secret configured for `attacker`'s org; `WebhooksController#verify_signature` passes because it only checks `repository_owner == attacker`.
5. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, which returns the `Commit` row belonging to `Stack A` (`victim-org/app`) as well, and calls `create_status_from_github!` on it — writing a forged `success` status onto the victim stack's commit and potentially triggering `stack.schedule_merges` for `Stack A`, an action the attacker has no legitimate access to perform on `victim-org/app`.

### Citations

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

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
