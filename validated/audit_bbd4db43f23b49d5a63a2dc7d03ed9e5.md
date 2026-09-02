### Title
Cross-Organization Forged CI Status via Webhook Signature/Repository-Binding Mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App Shipit deployment (as documented for `config/secrets.yml`, one App/`webhook_secret` per GitHub organization), the `WebhooksController` selects which `webhook_secret` to validate a webhook against using the attacker-controlled JSON field `repository.owner.login` (or `organization.login`), but the downstream `StatusHandler` that mutates data does not check the repository at all — it looks up commits purely by `sha` across the entire instance. This breaks the intended binding "organization that authenticated == repository/commit that is written."

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret` used for HMAC verification) based on `repository_owner`, which is read straight from the untrusted JSON body: [1](#0-0) [2](#0-1) 

The signature is verified with plain HMAC-SHA1 over the raw body using that org's secret: [3](#0-2) 

Once verified, `create` dispatches the *entire attacker-controlled payload* to all registered handlers for the event, with no re-check that the payload's other fields are consistent with `repository_owner`: [4](#0-3) 

For the `status` event, `StatusHandler#process` looks up commits **only by `sha`**, with zero repository/stack scoping — unlike the generic `Handler` base class, which does have a `stacks`/`repository_name` scoping helper that this handler does not use: [5](#0-4) [6](#0-5) 

Because JSON is fully attacker-controlled, `repository.owner.login` (used only for choosing the HMAC secret) and `sha` (used to select which commit record across the *whole instance* gets a new status) are two independent fields with no cross-validation. A tenant/org that is a legitimate customer of a multi-org Shipit instance (i.e., knows their own configured `webhook_secret`, e.g. by inspecting their own GitHub App settings) can:
1. Set `repository.owner.login` to their own org name — this makes `verify_signature` pick their own `webhook_secret`.
2. Set `sha` to the SHA of a commit belonging to a completely different, victim stack/repository tracked by the same Shipit instance.
3. Compute a valid `X-Hub-Signature` over this payload using their own known secret.
4. POST it to `/webhooks` with `X-Github-Event: status`.

`verify_signature` succeeds (their own secret matches their own signed payload), and `StatusHandler#process` finds and mutates the victim's `Commit` record because it matches purely on `sha`, oblivious to `repository_owner`.

### Impact Explanation
Successfully creating a forged `success` status record on a victim commit affects `Commit#deployable?`: [7](#0-6) 

and status creation directly schedules continuous delivery on `after_commit`: [8](#0-7) 

If the victim stack has `continuous_deployment` enabled and relies on required CI contexts (`ci.require`) to gate auto-deploys, an attacker with credentials for a *different, unrelated org configured on the same Shipit instance* can forge the required status context(s) for an arbitrary commit and trigger an unauthorized/unreviewed deploy — this is a cross-repository/cross-tenant integrity break resulting in an unauthorized deploy, matching the "Critical: unauthorized deploy" / "High: escalation" impact bar in scope.

### Likelihood Explanation
This requires: (a) the Shipit instance to be configured for multiple GitHub organizations (an explicitly documented, supported configuration in `docs/setup.md`), and (b) the attacker to be an onboarded, semi-trusted tenant with knowledge of their own org's `webhook_secret` (which they legitimately possess as the admin of their own installed GitHub App) but with no privilege over the victim's repository/stack. Given webhook signature checking is designed as the sole authentication gate for this endpoint (no session/API-token requirement), and the payload is otherwise fully attacker-supplied JSON, this is straightforward to exploit once the multi-org setup is in place. I could not fully verify how commonly multi-org configuration is deployed in practice, nor whether `sha` collisions across independently-hosted repos are common enough to matter — but an attacker can also simply push a commit with an attacker-chosen SHA-colliding tree/parent is unnecessary: the attacker only needs to *know* a target SHA (e.g., observable via the victim's public GitHub repo or Shipit UI), not create it.

### Recommendation
In `StatusHandler` (and any other handler not using `Handler#stacks`), scope status/commit lookups to the repository derived from the verified organization, e.g. require `Commit.joins(:stack => :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner })`, or otherwise cross-validate that the payload's `repository.owner.login` used for signature verification matches the repository owning the `Commit`/`Stack`. More generally, ensure every webhook handler enforces repository/stack scoping using data verified through the authenticated organization, not solely from unrelated payload fields.

### Proof of Concept
1. Shipit is configured (per `docs/setup.md`) with two GitHub orgs, `attacker-org` (attacker's own installed App, secret known to attacker) and `victim-org` (unrelated tenant), each tracked with its own stack.
2. Attacker crafts:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/circleci"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac_sha1(attacker_org_webhook_secret, raw_body)>`.
4. POST to `/webhooks` with `X-Github-Event: status` and the above signature.
5. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) succeeds using `attacker-org`'s secret.
6. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches `Commit.where(sha: params.sha)` — the victim commit — and creates a forged `success` `Status`, potentially unlocking continuous deployment for `victim-org`'s stack.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```
