### Title
Webhook signature verification authenticates the *organization* while `StatusHandler`/`PushHandler` act on data (commit `sha` / `repository.full_name`) that is never bound to that organization — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the HMAC against using only `repository.owner.login` (or `organization.login`) from the JSON payload, then verifies the raw body against that org's secret. Downstream handlers, however, act on completely different fields of that same attacker-controlled JSON body — `repository.full_name` in most handlers, and for `StatusHandler`, nothing repository-scoped at all (a bare `sha`). Anyone who legitimately controls a webhook secret for **one** organization configured in Shipit (a normal, unprivileged action if Shipit is set up for "Multiple GitHub Applications", or if any single org's app-management is compromised, which is explicitly in-scope per the "node key compromise" style threat model in the analog report) can forge a fully valid signature and then set the repository/commit fields to point at a completely different stack.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb#verify_signature` picks the app whose secret to check like this: [1](#0-0) 
`repository_owner` is read straight out of the same JSON body that will later be processed: [2](#0-1) 

The HMAC only proves "this body was signed with OrgA's `webhook_secret`" — it says nothing about which repository/organization the body's *content* claims to be about. Handlers, however, resolve the actual repository/stack to mutate from a **different, unrelated field** of the same body: [3](#0-2) 

`PushHandler` uses this to trigger `sync_github` on any stack matching `repository.full_name`/branch: [4](#0-3) 

`StatusHandler` is worse: it doesn't even scope to a repository — it looks up **any** `Commit` in the whole database by raw `sha` and writes a GitHub-status record onto it: [5](#0-4) [6](#0-5) 

So the equality the system is supposed to enforce — `organization that authenticated == organization/repository the payload is allowed to mutate` — does not hold. Only `organization that authenticated == whichever secret happened to validate the HMAC` is enforced; the repository/commit identity used for the actual write is taken from unauthenticated-relative-to-org fields inside the same body.

### Impact Explanation
Given a Shipit instance configured with multiple GitHub Apps/organizations (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications"), or in the "node/app key compromise" scenario used as the report's analog, an actor holding a webhook secret for one tenant org can:
1. Forge a `status` event with any known commit `sha` belonging to a stack under a *different* organization/repository and set `state: "success"`, `context:` to satisfy `required_statuses`/`blocking_statuses`, directly flipping `Commit#deployable?` on a stack it has no legitimate authorization over: [7](#0-6) . Combined with `continuous_deployment?`, this can trigger an actual deploy via `schedule_continuous_delivery`: [8](#0-7) .
2. Forge a `push` event whose `repository.full_name` names a foreign stack to force `GithubSyncJob`s against it, or forge `pull_request`/`check_suite` events to archive/unarchive review stacks belonging to a different repository, since all of these resolve the target purely from the JSON body's `repository.full_name`/`sha`, decoupled from the org whose secret validated the signature.

This crosses the "unauthorized deploy" / cross-repository-write bar called out as acceptable impact.

### Likelihood Explanation
Requires the attacker to hold a valid `webhook_secret` for *some* organization configured in the Shipit instance — not the target organization. This is a materially weaker requirement than compromising the target org's own credentials, and matches the report's accepted threat model of "an attacker gains access to one of several credentials that individually should not grant full control." Single-tenant Shipit deployments (one org, one webhook secret) are not exposed by this specific path since there is only one possible secret to forge with, but any multi-org deployment (explicitly documented and supported) is exposed.

### Recommendation
Bind the org identity used to select/verify the webhook secret to the same repository/organization value the handlers subsequently act on. Concretely: after selecting `github_app` by `repository_owner`, re-derive `repository_name` the same way `Handler#repository_name` does and reject the request (or reject the handler execution) unless `repository.full_name`'s owner segment matches the verified `repository_owner`. For `StatusHandler`, scope the `Commit` lookup by the stack(s) belonging to the repository resolved from the verified payload rather than a bare, repo-unscoped `sha` lookup.

### Proof of Concept
1. Configure Shipit with two GitHub Apps, `OrgA` (attacker-controlled webhook secret) and `OrgB` (victim, tracks stack `OrgB/critical-repo`), as shown in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a `status` event body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/decoy" },
  "sha": "<known sha of a commit in OrgB/critical-repo>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Sign the raw body with `OrgA`'s `webhook_secret` using `sha1=` HMAC, exactly as `GitHubApp#verify_webhook_signature` expects: [9](#0-8) .
4. `verify_signature` resolves `github_app = Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and the signature validates successfully.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — unscoped by repository — and marks the `OrgB` commit's status as success, potentially unblocking a deploy on a stack the attacker was never granted access to.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
