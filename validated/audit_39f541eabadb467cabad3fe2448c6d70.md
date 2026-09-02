### Title
Cross-repository commit status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController` verifies each incoming GitHub webhook's HMAC signature using the webhook secret configured for the organization named in the payload (`repository.owner.login` or `organization.login`), then dispatches the payload to an event handler that is expected to act only on the resources belonging to that authenticated repository/organization. `StatusHandler`, unlike its sibling handlers (`PushHandler`, `CheckSuiteHandler`), never scopes its lookup by repository — it resolves target `Commit` records purely by `sha`, globally across every stack/repository configured in the Shipit instance. This breaks the binding "organization that authenticated the webhook == repository whose data is written."

### Finding Description
`WebhooksController#verify_signature` selects the verifying secret via `repository_owner`, derived from the payload itself, and confirms the payload was legitimately signed by *that* organization's GitHub App configuration: [1](#0-0) [2](#0-1) 

The base `Handler` class provides a `stacks` helper that correctly scopes any query to only the repository named in the payload's `repository.full_name`: [3](#0-2) 

`PushHandler` and `CheckSuiteHandler` both use this `stacks` scoping before touching any commit data: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, ignores the `stacks`/repository scoping entirely and looks up commits by `sha` across the whole database: [6](#0-5) 

Because the webhook signature only proves the payload came from *some* organization that has a `Shipit.github(organization: ...)` configuration (i.e., any organization onboarded onto this Shipit instance, including one fully controlled by the attacker), an attacker who administers their own onboarded organization/repository can trigger a legitimate, correctly-signed `status` event for a commit whose SHA also exists in a *different* repository/stack they do not own (e.g., a fork sharing history with the upstream, or any repository that happens to contain the same commit object). `StatusHandler#process` will then attach that attacker-controlled `state`/`description`/`target_url` to the commit record in the victim's stack, because the lookup is not filtered by `repository_name`/`stacks`.

### Impact Explanation
Commit statuses gate `Commit#deployable?` / `Stack#blocked?` / `Stack#deployable?` (`success? && !blocked?`), which control continuous delivery and deploy eligibility: [7](#0-6) [8](#0-7) 

An attacker who controls a signed webhook from any onboarded organization can therefore forge a `success` status on a commit belonging to another repository/stack, potentially unblocking or triggering an unauthorized deploy of that commit — a cross-repository write and an unauthorized-deploy primitive, matching the Critical impact bar ("cross-repository writes, or an unauthorized deploy").

### Likelihood Explanation
Exploitation requires the attacker to control at least one organization/repository onboarded into the same Shipit instance (so they can send a validly-signed `status` webhook) and a commit SHA that is shared with the victim's tracked repository — realistic for forks, mirrors, or repositories with shared history/cherry-picks, all common in monorepo/fork-based workflows that Shipit is designed to support. No Shipit session, API token, or GitHub write access to the victim repository is required; the only requirement is a legitimately signed webhook for *any* organization known to this Shipit deployment.

### Recommendation
In `StatusHandler`, scope the `Commit` lookup to only commits belonging to the repository named in the payload, mirroring `Handler#stacks`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```

### Proof of Concept
1. Attacker onboards/administers `attacker-org/repo-fork`, a fork of `victim-org/target-repo`, on the same Shipit instance (both orgs configured with their own GitHub App/webhook secret).
2. Because `repo-fork` shares commit history with `target-repo`, commit `abc123...` exists identically (same SHA) in both.
3. Attacker triggers (or crafts, via GitHub API on their own repo) a `status` event for `repo-fork` with `sha=abc123...`, `state=success`, correctly signed with `attacker-org`'s webhook secret.
4. `WebhooksController#verify_signature` validates the signature using `attacker-org`'s secret and passes.
5. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, which also matches the corresponding commit row tracked under `victim-org/target-repo`'s stack, and creates a forged `success` status on it — with no check that the commit belongs to `repo-fork`.
6. If `target-repo`'s stack requires CI success for continuous deployment, this forged status can unblock/trigger deployment of that commit.

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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/stack.rb (L376-378)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
    end
```
