### Title
Cross-organization webhook forgery lets any onboarded org's GitHub App secret write commit statuses for any repository's commits, enabling unauthorized CI-gated deploys - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` verifies the HMAC signature of an incoming GitHub webhook using the secret belonging to whichever GitHub organization is *named in the unverified JSON payload* (`repository.owner.login` / `organization.login`), not the organization that the payload will actually be applied to. `Shipit::Webhooks::Handlers::StatusHandler`, which processes `status` events, then looks up the target `Commit` purely by `params.sha`, globally across the whole `commits` table, with no check that the commit belongs to a stack owned by the organization whose secret validated the request. This breaks the binding "organization whose secret authenticated the webhook" == "repository/stack whose data is mutated," matching the report's bug class (a validated field failing to bind to the object actually acted upon).

### Finding Description
`verify_signature` picks the `GithubApp` (and its `webhook_secret`) to verify against from attacker-controlled JSON before the signature has been checked: [1](#0-0) [2](#0-1) 

Once the signature is accepted (i.e. it matches the secret of *some* organization onboarded on this Shipit instance, `repository_owner`), the raw params are dispatched to handlers: [3](#0-2) 

The base `Handler` class does provide a `repository_name`/`stacks` helper scoped by `payload.dig('repository', 'full_name')`: [4](#0-3) 

However, `StatusHandler` (used for the `status` event) never uses this scoping at all — it resolves the target purely by SHA across every commit in the database: [5](#0-4) 

So the equality that should hold — "organization O whose secret validated `X-Hub-Signature`" == "organization that owns the stack/commit being mutated" — is never enforced for status events. Any organization legitimately onboarded to this Shipit instance (i.e., any org for which Shipit has been configured with a `webhook_secret`, per `lib/shipit/github_app.rb`'s `verify_webhook_signature`) can send a `status` webhook whose `repository.owner.login` is set to itself (so `Shipit.github(organization: repository_owner)` resolves to its own `GithubApp`/secret and the HMAC check passes), while the actual `sha` field references a commit belonging to a *different* organization's stack tracked by the same Shipit instance. `StatusHandler#process` will happily create/replace the commit's status for that unrelated stack: [6](#0-5) 

Commit status changes are not inert — they feed `Commit#deployable?` and `Commit#status`, which gate continuous delivery and manual deploy eligibility: [7](#0-6) [8](#0-7) 

By forging a `success` status with a whitelisted CI `context` for a victim commit, an attacker (who only controls their own org's onboarded GitHub App/webhook secret) can flip that commit into a deployable state on a stack it does not own, and — if continuous deployment is enabled on the victim stack — trigger `ContinuousDeliveryJob`, an unauthorized deploy.

### Impact Explanation
This crosses the "organization that authenticated" vs. "repository/stack that is written" boundary explicitly called out in scope: the org identity used to select the verifying secret is never re-checked against the org/stack that the status write actually targets. The consequence is a cross-repository write of CI status data and, downstream, the ability to satisfy `ci.require` gating and trigger an unauthorized deploy/continuous-delivery run on a victim stack — both explicitly listed as in-scope critical/high impacts (cross-repository writes, unauthorized deploy).

### Likelihood Explanation
Moderate. It requires the attacker to already be an onboarded organization on the shared Shipit instance (i.e., to have their own GitHub App/webhook secret configured — a normal, unprivileged-relative-to-other-tenants setup in a multi-org Shipit deployment), and to know the target commit SHA of a victim stack (visible via Shipit's own UI/API or GitHub itself, since SHAs aren't secrets). No GitHub write access to the victim repository, no Shipit session, and no `ApiClient` token are needed — only the ability to send an HTTP POST with a valid signature computed from the attacker's own org's secret.

### Recommendation
In `StatusHandler` (and any other handler that doesn't already scope by `stacks`/`repository_name`), require that the resolved `Commit`'s `stack.repository` matches `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, and additionally verify that this repository's owning organization matches `repository_owner` (the organization whose secret validated the signature) before applying any mutation. More generally, `verify_signature` should not select the verifying secret from unauthenticated payload data without subsequently re-binding that same organization identity to every object the handler mutates.

### Proof of Concept
1. Shipit instance is configured with two onboarded organizations, `org-attacker` (attacker's own org, has legitimate `webhook_secret` A) and `org-victim` (a separate customer org with stacks tracked in the same Shipit instance).
2. Attacker identifies a commit SHA `S` belonging to a stack owned by `org-victim` (visible via Shipit's public stack pages).
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "S",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-attacker" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(body, secret_A)>` using their own org's known secret `A`.
5. POST to `/github/webhooks` with header `X-Github-Event: status`.
6. `verify_signature` resolves `Shipit.github(organization: "org-attacker")`, verifies the signature successfully (it was computed with `org-attacker`'s own secret), and passes control to `StatusHandler`.
7. `StatusHandler#process` finds `Commit.where(sha: "S")` — the victim's commit — with no ownership check, and calls `create_status_from_github!`, writing a forged "success" status onto `org-victim`'s commit, potentially satisfying `ci.require` and enabling deployment/continuous delivery of that commit.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
