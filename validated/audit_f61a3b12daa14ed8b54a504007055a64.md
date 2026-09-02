### Title
Webhook signature check is keyed to an attacker-chosen "organization" field while the event is applied to any repository/commit named in the same unverified payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App / webhook secret to validate the request against using a field pulled straight out of the untrusted JSON body (`repository.owner.login` or `organization.login`), not from anything that is itself authenticated. The event is then dispatched to handlers that act on a *different* field of the same body — the repository full name (or, for `status` events, nothing at all) — with no check that the two agree. This is the same class of bug as the oracle report: a value that is trusted to authorize an action (`currentLiquidityEvaluation` / here, "which org's secret authenticated this request") is decoupled from the value the action is actually performed against (the pair being priced / here, the repository or commit being written to).

### Finding Description
`WebhooksController#verify_signature` picks the signing organization from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` loads that organization's `GitHubApp`, and `verify_webhook_signature` is only meaningful if a `webhook_secret` was configured for *that specific organization*: [3](#0-2) 

Per the documented setup, `webhook_secret` is optional per-organization and multiple orgs can be configured side by side in `config/secrets.yml`: [4](#0-3) [5](#0-4) 

If any configured organization has no `webhook_secret` set, `verify_webhook_signature` returns `true` unconditionally for a payload whose `repository.owner.login`/`organization.login` names that org — regardless of the (missing or garbage) `X-Hub-Signature` header. After this check "passes," the controller dispatches the entire, attacker-controlled body to handlers: [6](#0-5) 

Handlers do not re-verify that the repository they act on belongs to the organization that "authenticated" the request:
- `Handler#stacks` resolves purely by `repository.full_name` string match, with no organization binding to the org used in `verify_signature`: [7](#0-6) 
- `StatusHandler` doesn't even use a repository field — it matches globally by commit SHA across the entire Shipit instance: [8](#0-7) 
- `PushHandler` triggers a sync against `stacks` resolved the same unscoped way: [9](#0-8) 

The broken equality is: *"organization whose secret validated `X-Hub-Signature`" should equal "organization that owns the repository/commit the handler mutates."* Nothing in the controller or in `Handler#stacks`/`StatusHandler`/`PushHandler` enforces this. As with the oracle bug — where the pool used to weight the price was not verified to be the same pool being priced — here the org used to authorize the webhook is not verified to be the org that is actually written to.

### Impact Explanation
An attacker who can reach `/webhooks` (an unauthenticated, internet-facing endpoint by design) and knows (or guesses) the name of any GitHub organization configured in this Shipit instance that has no `webhook_secret` set can forge:
- `status` events for **any commit SHA on any stack**, via `Commit.create_status_from_github!`, setting state to `success` — which feeds `Status::Group`/`StatusChecker` used by `MergeRequest#all_status_checks_passed?` and `Commit#deployable?`, potentially unblocking an unauthorized merge or continuous deployment for a commit the attacker chose. [8](#0-7) [10](#0-9) 
- `push` events forcing `GithubSyncJob`/`sync_github` on any stack matching a spoofed `repository.full_name`, independent of which org actually owns that repository in GitHub. [9](#0-8) 
- `membership`/`pull_request` events attributed to a repository/org the attacker does not control.

This crosses the "unauthorized deploy, rollback, or merge" Critical bar and the "unauthenticated ... write" boundary for stacks belonging to organizations other than the one nominally used to authenticate.

### Likelihood Explanation
This requires only that at least one configured GitHub organization in the deployment omits `webhook_secret` (explicitly supported/"optional" per `docs/setup.md`), which is a realistic multi-tenant configuration (e.g., an internal/low-risk org left unsecured while others use secrets). No credential, session, or repository access is needed — the flaw is purely in the missing cross-check between the authenticating field and the acted-upon field, both drawn from the same unauthenticated JSON body.

### Recommendation
- Require `webhook_secret` to be present for every configured organization (fail closed if absent), rather than treating a missing secret as "always verified."
- After signature verification, re-derive the repository/organization strictly from GitHub's authenticated context (not the JSON body) and confirm it matches `repository_owner`/the org whose secret validated the signature before dispatching to handlers.
- Scope `StatusHandler` (and any other handler) to the repository declared in the signed payload rather than matching commits globally by SHA.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgSecure` (has `webhook_secret`) and `OrgOpen` (no `webhook_secret`), as shown in `docs/setup.md` §"Using Multiple Github Applications".
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "organization": { "login": "OrgOpen" },
  "sha": "<any-commit-sha-tracked-by-OrgSecure's-stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
No valid `X-Hub-Signature` is required because `repository_owner` resolves to `OrgOpen`, whose `verify_webhook_signature` short-circuits to `true` (`lib/shipit/github_app.rb:76-77`).
3. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches the commit purely by SHA across the whole instance and creates a `success` status for it, with no relation to `OrgOpen` at all — potentially satisfying required checks for a stack that belongs to `OrgSecure` and enabling an unauthorized merge/deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
