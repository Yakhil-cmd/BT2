Found the key mismatch: `WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using the **unsigned, attacker-controlled payload body itself** (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), then hands the same raw, already-trusted payload to the handlers, which separately derive the target `Stack`/`Repository` via `payload.dig('repository', 'full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`. [1](#0-0) [2](#0-1) 

However, after tracing through, this does not amount to a cross-repository write in a single-tenant sense: an attacker would need a valid `webhook_secret` for *some* organization Shipit is configured for (i.e., already a repository/org owner with write access to their own webhook config) in order to produce a signature that passes `verify_webhook_signature`, and then set `repository.full_name` in the payload body to a *different, victim* org/repo string to make `Repository.from_github_repo_name(repository_name)` resolve to a target stack outside the attacker's own organization — because the field used to select which secret verifies the signature (`repository.owner.login` / `organization.login`) is never cross-checked against the field used to select which repository the handlers act on (`repository.full_name`). This is exactly the "org authenticated versus repository written" binding called out in the rules: the org whose secret authenticates the signature is never bound to equal the repo the handlers then update. [3](#0-2) [4](#0-3) 

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while handlers act on the independently-supplied `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the `GithubApp`/`webhook_secret` used to validate `X-Hub-Signature` based on `repository_owner`, computed from the payload's `repository.owner.login` (or `organization.login`) field. Once the signature check passes, the entire raw JSON body — including a separately-read `repository.full_name` field — is handed unmodified to `Shipit::Webhooks.for_event(event)` handlers, which resolve the target `Stack`/`Repository` via `Handler#repository_name` (`payload.dig('repository', 'full_name')`). Nothing enforces that `repository.full_name` belongs to the same organization as `repository.owner.login`/`organization.login`.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and uses it purely to select which org's `webhook_secret` HMAC-validates the payload:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 

Once verified, `create` parses the same raw body and dispatches it unchanged to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
end
``` [5](#0-4) 

Handlers derive the affected repository/stack from a *different* field of the same payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

The equality that should hold — "the org whose `webhook_secret` authenticated this payload == the org that owns the repository being mutated" — is never asserted. `repository.owner.login`/`organization.login` (used for signature-key selection) and `repository.full_name` (used for repository resolution) are independent JSON fields inside the same self-signed HTTP body, so a party controlling a single valid GitHub organization's `webhook_secret` can craft a payload whose `repository.owner.login` matches their own org (to pick the correct verifying key) while `repository.full_name` names any other org/repo Shipit tracks, causing sync/merge/status/membership handlers to write against a stack that has nothing to do with the authenticating org.

### Impact Explanation
This crosses the "cross-repository writes" Critical bucket named in the rules: an entity legitimately possessing only one organization's webhook secret (not privileged for any other org/repo in the Shipit instance) could push forged `push`, `status`, `check_suite`, `pull_request`, or `membership` events that get applied to a completely different repository's `Stack`/`Repository`/`Commit`/`MergeRequest` records — e.g., injecting fabricated commit statuses, or manipulating `MergeRequest` merge-queue state, of a repository they don't own.

### Likelihood Explanation
Requires access to a legitimate GitHub webhook secret for at least one org configured in the Shipit instance (a realistic bar for a multi-tenant Shipit install, e.g., an org admin or anyone who can read that org's Shipit `secrets.yml`/webhook config), plus knowledge of another tracked repository's `full_name`, which is public information. No repository write access or Shipit session/API token is required to exploit — only the ability to send an HTTP POST with a validly-signed body to the shared `/github/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), assert that the repository resolved from `repository.full_name` belongs to the same organization used to select the verifying `webhook_secret` — e.g., reject the event if `repository.full_name.split('/').first.downcase != repository_owner.downcase`, or resolve the target `Repository`/`Stack` using `repository_owner` rather than trusting a second independent payload field.

### Proof of Concept
1. Attacker controls (or has been given) the webhook secret for `attacker-org` in the multi-tenant Shipit config.
2. Attacker crafts a payload: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, ...}` for e.g. a `status` event with a fabricated passing CI state for a `victim-org/victim-repo` commit.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the raw JSON body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` (derived from `repository.owner.login`), successfully verifies the signature using `attacker-org`'s secret.
5. `create` dispatches the full payload to the `status` handler, which resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and creates a forged `Status` record against `victim-org`'s commit, potentially unblocking that stack's merge queue (`MergeRequest#all_status_checks_passed?`) despite the attacker having no relationship to `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
