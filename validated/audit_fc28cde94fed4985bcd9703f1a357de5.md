### Title
Cross-Repository Commit Status Injection via Unscoped `StatusHandler` Webhook - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `WebhooksController` verifies an incoming GitHub webhook's HMAC signature against the *organization* named in the payload (`repository.owner.login` or `organization.login`), but the `status` event handler then mutates commit state by matching **only on the raw SHA**, with no check that the SHA actually belongs to the repository/organization whose signature was verified. This breaks the same class of binding described in the external report: a value that authorizes an action (here, "the org that signed the webhook") is not the same value that the action is actually scoped to (here, "the repository/commit that gets written").

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App config to verify against using only `repository_owner`, i.e. the organization login taken from the payload: [1](#0-0) 

Once the signature check passes for that organization, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, whose `process` method looks up commits **globally by SHA**, with no repository scoping at all: [2](#0-1) 

This is inconsistent with the base `Handler` class, which explicitly provides a `stacks` helper that scopes lookups to the repository named in the payload (`payload.dig('repository', 'full_name')`): [3](#0-2) 

Other handlers such as `PushHandler` and `CheckSuiteHandler` correctly use this `stacks` scoping before touching any commit: [4](#0-3) 

`StatusHandler` is the outlier: it never calls `stacks`/`repository_name`, so `Commit.where(sha: params.sha)` matches **any** commit row in the entire database sharing that SHA, regardless of which `Stack`/`Repository`/organization it belongs to, and then writes a GitHub-originated status onto it via `create_status_from_github!`: [5](#0-4) 

Since Shipit supports multiple GitHub organizations each with their own `webhook_secret` (as shown in the multi-org secrets template), the equality the app implicitly relies on is: `organization that signed the webhook == organization/repository whose commit gets written`. `StatusHandler` breaks this equality — the signature only proves "some configured org sent this", but the write target is chosen purely by SHA collision, independent of org/repo. [6](#0-5) 

### Impact Explanation
Commit status controls deployability: `Commit#deployable?` requires `success?` (derived from `statuses`/`status` state) and absence of blocking statuses. [7](#0-6) 

An attacker who controls (or has push/status-setting rights in) any repository within an organization configured in Shipit can forge a `status` webhook body naming a SHA that happens to exist as a commit in a *different, unrelated* stack's repository (trivially achievable for identical/forked git history, since SHA1 is fully determined by commit content and is not required to be repo-unique in this schema). The resulting webhook is legitimately signed by GitHub for the attacker's own org/repo, passes `verify_signature`, and `StatusHandler` then writes a `success` (or any) status onto the victim commit in a completely different stack — satisfying required statuses and potentially triggering an unauthorized deploy of that other stack. This matches the report's "Critical: cross-repository writes / an unauthorized deploy" impact bucket.

### Likelihood Explanation
Exploitation requires the attacker to be able to trigger a genuine `status` webhook for a repository they control within a Shipit-configured GitHub organization (e.g., by pushing/forking identical commit content and posting a status via the GitHub API on their own repo) — no Shipit session, API token, or webhook secret is needed, only ordinary GitHub write access to some repo in the org. This is a realistic path in any multi-tenant / multi-repository organization setup, which the engine explicitly supports.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` and `CheckSuiteHandler` do: restrict the commit lookup to `stacks` derived from `payload.dig('repository', 'full_name')` (or equivalently `Repository.from_github_repo_name(repository_name)`) before matching by SHA, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
```

### Proof of Concept
1. Shipit is configured with two organizations, `victim-org` (tracking `victim-org/app`) and `attacker-org` (tracking `attacker-org/sandbox`), each with its own `webhook_secret`.
2. Attacker forks/recreates a commit in `attacker-org/sandbox` that is byte-identical (and thus SHA1-identical) to a commit `C` currently pending in `victim-org/app`'s tracked stack.
3. Attacker uses the GitHub API (with normal write access to their own repo) to set a `success` status on that commit in `attacker-org/sandbox`.
4. GitHub sends a `status` webhook to Shipit signed with `attacker-org`'s `webhook_secret`; `WebhooksController#verify_signature` validates it because it only checks the org identified by `repository_owner` (`attacker-org`).
5. `StatusHandler#process` executes `Commit.where(sha: <C's sha>)`, which matches commit `C` in `victim-org/app`, and calls `commit.create_status_from_github!`, marking `C` as successful — potentially satisfying required statuses for an unauthorized deploy on `victim-org/app`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
