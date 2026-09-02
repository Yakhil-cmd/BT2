### Title
Cross-repository commit status forgery via unscoped SHA lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
GitHub `status` webhooks are authenticated per-organization based on the `repository.owner.login` in the payload, but `StatusHandler#process` applies the status update to *any* `Commit` row across the entire database that matches the given SHA, with no check that the SHA actually belongs to the repository/organization whose signature was verified. This breaks the binding: "organization authenticated == repository written."

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App config to verify the signature by reading `repository_owner` out of the untrusted JSON payload (`params.dig('repository', 'owner', 'login')`), then checks the signature against that organization's `webhook_secret`: [1](#0-0) [2](#0-1) 

This only proves the request was signed by *that organization's* secret — it says nothing about which repository/commit the event handler is allowed to mutate.

Most handlers correctly re-derive the target scope from the same payload's `repository.full_name` before acting, e.g. `PushHandler` and `CheckSuiteHandler` scope to `stacks` (derived from `Handler#repository_name`) and additionally filter by branch/sha within that scope: [3](#0-2) [4](#0-3) [5](#0-4) 

`StatusHandler`, however, ignores `repository_name`/`stacks` entirely and looks up commits globally by SHA: [6](#0-5) 

Because git SHA-1s are content-addressed, the same commit SHA can legitimately exist in multiple repositories tracked by the same Shipit instance (forks, subtree/vendor imports, repo migrations/renames, shared upstream history). An organization whose webhook signature validates successfully for its *own* repository can submit a `status` payload whose `sha` matches a commit belonging to a completely different stack/organization's repository. `StatusHandler` will happily write the attacker-controlled `state`/`description`/`target_url`/`context` onto that foreign commit via `Commit#create_status_from_github!`, even though the signature check never authenticated against that other organization at all.

### Impact Explanation
Commit statuses feed directly into deploy-gating logic (`Commit#deployable?` / `Stack#deployment_checks_passed?`, as seen from `deployable?` composing `!locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?`) [7](#0-6) . An attacker who controls one legitimately-configured GitHub organization/repository in the Shipit instance can forge a `success` status for a colliding SHA in an unrelated stack, potentially marking an otherwise non-deployable/failing commit as deployable and enabling an unauthorized deploy on a stack/repository they were never authenticated against — a cross-repository write of state that gates production deploys, without ever gaining that other repository's webhook secret.

### Likelihood Explanation
Requires the attacker to control (or have compromised, at a level already assumed “unprivileged” per this engine's own webhook auth model — a valid configured GitHub App/webhook for one org) at least one repository configured in the same Shipit installation, and for a target SHA to coincide with a commit tracked under a different stack (realistic for forks, vendored/subtree commits, or monorepo split histories, all common in engineering orgs running a shared Shipit instance). This is a real, exploitable logic gap rather than a purely theoretical one, since the code path performs zero repository-scoping by design.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository whose ownership was verified for the request, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` (as `CheckSuiteHandler` already does), rather than a bare `Commit.where(sha: params.sha)` across all repositories.

### Proof of Concept
1. Attacker controls organization `attacker-org`, which owns repository `attacker-org/repo-x`, properly configured in Shipit with its own `webhook_secret`.
2. Attacker forks or otherwise obtains a repository whose commit history overlaps with `victim-org/repo-y` (also tracked in the same Shipit instance), so that some commit SHA `S` exists in both.
3. Attacker sends a `status` webhook to Shipit with `repository.owner.login = "attacker-org"`, correctly signed with `attacker-org`'s webhook secret, and `sha = S`, `state = "success"`.
4. `WebhooksController#verify_signature` validates the signature against `attacker-org`'s secret and passes.
5. `StatusHandler#process` executes `Commit.where(sha: S)`, which also matches the commit in `victim-org/repo-y`'s stack, and calls `create_status_from_github!` on it, marking it successful and potentially unlocking deploy checks for `victim-org/repo-y` — a repository/organization the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/stack.rb (L376-378)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
    end
```
