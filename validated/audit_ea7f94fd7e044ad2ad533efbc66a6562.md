### Title
Cross-organization/cross-repository forgery via `webhooks_controller.rb`'s org-scoped signature check not binding to the payload's target repository/commit - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify against using `repository_owner`, a value taken from the payload itself (`repository.owner.login` or `organization.login`), then defers entirely to that org's `webhook_secret`. But the code that actually *acts* on the payload — `Shipit::Webhooks::Handlers::Handler#repository_name` (`payload.dig('repository', 'full_name')`) and, more severely, `StatusHandler#process` (`Commit.where(sha: params.sha)`) — never re-checks that the acted-upon repository/commit actually belongs to the organization whose secret was used to authenticate the request.

### Finding Description
The controller picks the verifying org from attacker-controlled payload fields: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly *bypasses* verification entirely when the selected org has no `webhook_secret` configured: [3](#0-2) 

`webhook_secret` is documented and shown as an optional/nil field in the shipped configuration examples (e.g. `webhook_secret: # nil`): [4](#0-3) [5](#0-4) 

Once "verified" (or trivially bypassed for a secret-less org), the actual target of the mutation is picked from a *different, unverified* payload field — `repository.full_name`, not `repository.owner.login`: [6](#0-5) 

This binding gap is worst in `StatusHandler`, which doesn't even scope by repository at all — it matches by bare `sha` across the entire instance-wide `Commit` table: [7](#0-6) [8](#0-7) 

The equality that should hold and is broken: `organization authenticated by verify_signature (repository_owner / webhook_secret)` == `repository/commit actually mutated (repository.full_name / bare sha lookup)`. Before the attack, GitHub itself guarantees these two fields are consistent because it constructs the payload from the real event source. After the attack (a forged POST directly to the webhook endpoint), an attacker can set `repository.owner.login` to any organization name configured in Shipit (in particular, one deployed without a `webhook_secret`, satisfying the "no webhook_secret" instrument entirely, no credential needed) while setting `repository.full_name` (or `sha`, for `StatusHandler`) to any repository/commit tracked anywhere in the same Shipit instance, including ones belonging to a completely different organization.

### Impact Explanation
Commit statuses gate whether a commit is `deployable?` (`success? && !blocked?`) and drive `schedule_continuous_delivery`, which can trigger `ContinuousDeliveryJob` for stacks with `continuous_deployment?` enabled: [9](#0-8) [10](#0-9) 

By forging a `status` webhook event that is signature-"verified" against an org whose `webhook_secret` is unset (a supported, documented configuration), an unprivileged remote attacker can inject a fabricated `success` status for any known commit SHA belonging to any stack tracked by the Shipit instance — including stacks under organizations completely unrelated to the one used to pass signature verification. This can defeat CI-gating and trigger an unauthorized/unreviewed deploy via continuous delivery. Similarly, `push`, `pull_request`, `check_suite`, and `membership` handlers resolve their target via `repository.full_name` rather than the verified `repository_owner`, letting a forged request from a secret-less org sync/archive/unarchive review stacks or create teams/users tied to a different repository/organization than the one that was authenticated.

### Likelihood Explanation
This requires no session, API token, or webhook secret knowledge for at least one instance-configured organization that has `webhook_secret` left blank — a configuration explicitly presented as valid/default in the engine's own shipped config examples. Multi-tenant Shipit deployments (as demonstrated by `secrets_double_github_app.yml` supporting multiple orgs) make this more likely to trigger, since only one org among many needs to be secret-less to compromise cross-org integrity for the whole instance. Commit SHAs are not secret (visible via GitHub UI/API/PR links), making the `StatusHandler` path trivial to target for known commits.

### Recommendation
1. Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank; either require a secret for every configured GitHub App or fail closed.
2. After signature verification, re-derive/verify that `repository.full_name`'s owner matches the `repository_owner` used to authenticate, rejecting mismatches.
3. In `StatusHandler`, scope the `Commit` lookup by the verified repository (via `stacks`/`repository_name`) instead of a bare, instance-wide `sha` match.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `OrgA` (no `webhook_secret`) and `OrgB` (tracked stacks with real deploy pipelines), as shown supported in `secrets_double_github_app.yml`.
2. POST directly to `/github/webhooks` with header `X-Github-Event: status`, no `X-Hub-Signature` needed, and body:
```json
{
  "organization": { "login": "OrgA" },
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/anything" },
  "sha": "<known-sha-of-OrgB-commit>",
  "state": "success"
}
```
3. `verify_signature` resolves `repository_owner` = `OrgA`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`).
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matching the target commit in `OrgB`'s stack regardless of the authenticated `OrgA` context, creating a forged `success` status that can unblock/trigger an unauthorized deploy for `OrgB`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-9)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
