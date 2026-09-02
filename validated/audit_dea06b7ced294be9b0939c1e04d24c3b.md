## Analog Found

### Title
Webhook signature is verified against an org selected from an unvalidated payload field, while handlers act on a different, uncorrelated payload field — allowing cross-repository forged events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* `GitHubApp`/webhook secret to verify a webhook against using `repository_owner`, derived from the untrusted, not-yet-verified payload (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Once the signature check passes, the controller dispatches the *entire* raw payload to event handlers (`app/controllers/shipit/webhooks_controller.rb`), which resolve the target `Stack`/`Commit` using a **different** field from the same payload (`repository.full_name` in `Handler#repository_name`, or a bare `sha` lookup in `StatusHandler`). Nothing enforces that these two fields refer to the same repository/organization. This breaks the intended binding "organization whose secret authenticated the request == repository/commit that gets written to," analogous to the Notional bug class where a value used for one purpose (staking) is decoupled from the value that is actually checked/acted upon.

### Finding Description
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from the raw, unauthenticated JSON body and uses it to select the `GitHubApp` instance (and thus the webhook secret) to validate the HMAC signature:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
head(422) unless verified
```
- Once verified, `create` forwards the same raw `params` to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`.
- `Handler#stacks` / `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) resolve the target stack from `payload.dig('repository', 'full_name')` — a field independent of `repository.owner.login` used for signature selection.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) is even more decoupled: it looks up commits **globally by `sha`** (`Commit.where(sha: params.sha)`) with no repository/organization scoping at all, and calls `commit.create_status_from_github!(params)` for every matching commit across every stack in the installation.
- `Status` creation triggers `schedule_continuous_delivery` (`app/models/shipit/status.rb:19,42-44`), which can trigger an actual deploy if a stack has continuous deployment enabled and the forged status is `success`.

This means the "organization the request authenticates as" (`repository_owner`, used only to pick the HMAC secret) and "the repository/commit actually written to" (`repository.full_name` / bare `sha`) are never checked for equality. For a Shipit instance configured with multiple GitHub orgs (`docs/setup.md` "Using Multiple Github Applications" section), an attacker who legitimately controls the webhook secret for **one** configured organization (e.g., they administer their own GitHub App/org that is also connected to this same Shipit instance) can craft an arbitrary raw JSON body — not a real GitHub-delivered webhook — where:
- `repository.owner.login` = "attacker-org" (so `verify_signature` selects the attacker's known secret and the HMAC passes), while
- `repository.full_name` = "victim-org/victim-repo" (or simply a known commit `sha` belonging to a victim stack).

Because the endpoint is a plain unauthenticated HTTP POST protected only by this HMAC check, the attacker directly signs their crafted body with their own known secret and posts it to `/webhooks`.

### Impact Explanation
- Via `StatusHandler`, an attacker can inject a forged `success` `Status` on any known commit `sha` belonging to *any* stack on the Shipit instance, without needing any credentials tied to that stack's organization. If that stack has `continuous_deployment` enabled, this results in an **unauthorized deploy** being scheduled (`Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery`).
- Via `PushHandler`, the attacker can force `GithubSyncJob` and downstream syncing to run against a victim stack outside their organization, which is at minimum an authorization boundary violation (acting on a repository whose org they were never authenticated for).
- This matches the report's "Impact: Critical — unauthorized deploy" / cross-repository write category, since the deploy trigger for the victim stack does not depend on any credential belonging to the victim's org — only on the attacker's own webhook secret and knowledge of a victim commit sha.

### Likelihood Explanation
Requires:
1. The Shipit deployment to be configured with multiple GitHub organizations (a documented, supported configuration), giving the attacker legitimate knowledge of one org's webhook secret.
2. The attacker to know a target commit `sha` (often public, e.g., visible on GitHub) belonging to a stack with continuous deployment enabled.
No GITHUB_TOKEN, ApiClient token, or session is required — only a raw HTTP POST to the public `/webhooks` endpoint with a validly computed HMAC using a secret the attacker legitimately possesses for their own org. This satisfies the "unprivileged attacker" constraint since knowledge of one's own GitHub App webhook secret is not a privilege over the victim's stack.

### Recommendation
Bind signature verification to the same identity used for repository/commit resolution: verify the signature using the organization derived from `repository.full_name` (or reject payloads where `repository.owner.login` does not match the owner segment of `repository.full_name`). Additionally, scope `StatusHandler`/`Handler#stacks` lookups to the verified `repository_owner`/organization rather than trusting unrelated fields in the same unauthenticated payload, e.g., filter `Commit.where(sha: params.sha)` by `stack.repository.owner == verified_organization`.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `docs/setup.md` multi-org config).
2. Attacker (who administers the GitHub App for `attacker-org`) knows `attacker-org`'s `webhook_secret`.
3. Attacker crafts a raw JSON body for a `status` event:
```json
{
  "sha": "<known victim commit sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/irrelevant" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches that org's `GitHubApp`, and the HMAC matches → request passes.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` (global lookup, no org scoping) and creates a `success` `Status` on the victim's commit, triggering `schedule_continuous_delivery` for the victim's stack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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
