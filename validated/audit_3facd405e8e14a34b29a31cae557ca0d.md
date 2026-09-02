### Title
Cross-repository commit status forgery via unscoped `sha` lookup in webhook `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook against the webhook secret of a **single organization**, derived from the payload's `repository.owner.login` [1](#0-0) . That authentication only proves "this payload was sent by GitHub on behalf of organization X". However, `Shipit::Webhooks::Handlers::StatusHandler#process` uses the authenticated payload to write to **every** `Commit` record across the entire Shipit instance that happens to share the same `sha`, without ever checking that the commit belongs to a stack whose repository matches the organization/repository that was actually authenticated [2](#0-1) .

### Finding Description
The binding that should hold is: `organization authenticated by verify_webhook_signature == repository whose commits are mutated`. Compare the two handlers:

- `CheckSuiteHandler` and `PushHandler` correctly scope their mutation through `stacks`, which resolves repositories via `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository', 'full_name')` [3](#0-2) , [4](#0-3) .
- `StatusHandler`, by contrast, ignores the `repository` field entirely and looks up commits purely by `sha`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

`WebhooksController#verify_signature` selects the GitHub App/webhook secret to check against using `repository_owner`, which is read from the very same untrusted payload (`params.dig('repository','owner','login')` or the `organization` object) [5](#0-4) . This is fine as an authentication step (GitHub itself computed the HMAC over the payload including that repository field, so an attacker cannot forge a payload claiming to be a different org). But the signature only proves the *sender's own organization/repository* is legitimate — it says nothing about which `Commit` rows in Shipit's database should be affected. `StatusHandler` never re-checks that the commit it writes into belongs to a stack for the *same* repository that was authenticated.

Because Git commit SHAs are hashes of tree/parent/author/committer/message content, two independent repositories that share history (a very common situation for forks, mirrors, or repos ingested from a shared upstream) will contain commits with identical SHAs. Any GitHub organization/repository that:
1. has the Shipit GitHub App installed (a normal, low-privilege, self-service action for repo owners — not a Shipit credential), and
2. shares a commit SHA with a commit already known to a *different* organization's Shipit stack (e.g., because that other repo is a downstream fork/mirror of a shared codebase),

can send a real, GitHub-signed `status` event for their own repository whose `sha` collides with a commit in someone else's stack. Shipit will pass `verify_webhook_signature` (correctly, for the attacker's own org), then `StatusHandler` will attach the (attacker-chosen) status/state/description/target_url onto the victim stack's `Commit` via `commit.create_status_from_github!(params)`, even though that commit was never touched by the victim's actual CI or repository.

### Impact Explanation
Commit statuses feed directly into Shipit's deployability logic (blocking statuses / commit deployability checks used by `Stack#trigger_deploy` and related flows). Forging a passing (`success`) status onto a commit in a stack the attacker has no access to can make an otherwise CI-failing or unchecked commit appear deployable, enabling an **unauthorized deploy** decision to be reached for a repository/organization the attacker does not control — one of the explicitly accepted Critical impacts (unauthorized deploy). It also lets the attacker forge failing statuses or arbitrary `target_url`/`description` content associated with a victim's commit history, corrupting audit/status data cross-tenant.

### Likelihood Explanation
This requires no Shipit credentials, no GitHub App private key, and no privileged account — only that the attacker (a) controls a GitHub repository that has the Shipit GitHub App installed by its own organization (self-service, low privilege) and (b) can produce or reuse a commit whose SHA collides with a target commit already tracked by another onboarded stack (realistic for shared upstream/fork/mirror scenarios, which are common in multi-tenant Shipit deployments serving many teams off a shared codebase). No SHA-1 collision attack is required — only naturally identical commits from shared history.

### Recommendation
Scope `StatusHandler#process` the same way `CheckSuiteHandler`/`PushHandler` do: restrict the `Commit` lookup to commits belonging to `stacks` (i.e., stacks whose `Repository.full_name` matches `payload.dig('repository', 'full_name')`), instead of a bare `Commit.where(sha: params.sha)` across the whole database.

### Proof of Concept
1. Organization `attacker-org` installs the Shipit GitHub App on `attacker-org/forked-repo`, a public fork/mirror sharing history with `victim-org/target-repo`, which is already tracked as a Shipit stack.
2. `attacker-org` triggers (or synthesizes via their own CI) a `status` webhook event on `attacker-org/forked-repo` for a commit `sha` that is identical to a commit `C` present in `victim-org/target-repo`'s Shipit stack (shared ancestor commit), with `state: "success"`.
3. GitHub signs this payload with `attacker-org`'s webhook secret and POSTs it to Shipit's `/webhooks`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches commit `C` belonging to `victim-org/target-repo`'s stack, and calls `commit.create_status_from_github!(params)`, injecting a forged "success" status onto the victim's commit [2](#0-1) .
6. The victim stack's deployability checks now see a false "success" status for commit `C`, potentially unlocking a deploy the victim organization's own CI never approved.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
