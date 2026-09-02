### Title
Webhook signature validated against `repository.owner.login`, but `status` and `push` handlers act on unscoped/attacker-controlled `sha`/`full_name` fields from the same unverified-binding payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, read from the payload itself (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`). Once that org's secret validates the signature, the *entire* raw body is treated as trusted and handed to event handlers, which act on **different, independently-controlled fields** of the same JSON body — most notably `Shipit::Webhooks::Handlers::StatusHandler`, which resolves target rows only by `sha` with **no repository/organization scoping at all**. [1](#0-0) [2](#0-1) 

### Finding Description
The binding that should hold is: *the organization whose secret authenticated the webhook == the organization whose data is written by the handler*. This binding is broken:

1. `verify_signature` derives `repository_owner` from the payload's `repository.owner.login`/`organization.login` and looks up `Shipit.github(organization: repository_owner)` to fetch that org's `webhook_secret`, then verifies the HMAC over the full raw body with that secret. [3](#0-2) 

2. Once verification passes (using whichever org's secret matched the `repository_owner` value the attacker chose to put in the payload), `create` forwards the *entire attacker-supplied JSON* unfiltered to `Shipit::Webhooks.for_event(event)` handlers. [4](#0-3) 

3. `Shipit::Webhooks::Handlers::Handler#stacks` (used by e.g. `PushHandler`) scopes writes using `payload.dig('repository', 'full_name')` — a field distinct from `repository.owner.login` used for signature-org selection, and never cross-checked against it. [5](#0-4) 

4. Worse, `StatusHandler#process` doesn't even use `repository` at all — it looks up matching commits **globally** by `sha`: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. Any commit in the entire Shipit instance sharing that SHA (which occurs naturally when the same commit/tag is present in forks or is guessable/known to the attacker from public history) is written to, irrespective of which organization owns it. [6](#0-5) 

An attacker who knows the `webhook_secret` for *any one* org configured on the shared Shipit instance (e.g. their own organization's webhook secret, obtained legitimately via GitHub App/webhook settings for a repo they administer) can craft a raw POST to `/webhooks` with `X-Github-Event: status`, set `repository.owner.login` (or `organization.login`) to their own org so signature verification succeeds with a secret they know, while setting `sha` to an arbitrary commit hash belonging to a **different** organization's stack tracked by the same Shipit instance. `verify_signature` will pass because the org-selection field matches the secret they control, but the actual mutation target (`Commit.where(sha:)`) is completely disconnected from that org.

### Impact Explanation
Shipit commit statuses gate CI-based deploy eligibility (`Shipit::Commit#create_status_from_github!` and related significant-status aggregation used by `Stack`). By forging a passing/`success` status for an arbitrary commit SHA belonging to a victim organization's stack — using only a webhook secret the attacker legitimately possesses for an unrelated, less-privileged org on the same multi-tenant Shipit instance — an attacker can flip CI gating to green and enable an unauthorized deploy of that commit on the victim's stack, without ever needing write access to the victim's repository or its GitHub App/webhook secret. This matches the Critical "unauthorized deploy" impact category from the rules.

### Likelihood Explanation
This requires the deployment to run Shipit's documented multi-organization mode (`config/secrets.yml` `github:` keyed by multiple orgs, each with its own `webhook_secret`), which is an explicitly supported and documented configuration. [7](#0-6) 
Within that configuration, any org onboarded to the shared instance — even one with low trust/importance — effectively becomes a pivot to forge status events for every other org's commits, because `StatusHandler` performs no per-organization scoping whatsoever. No compromise of the victim org's own secret, GitHub App, or repository access is needed, only knowledge of one (any) configured org's `webhook_secret`, which is unprivileged relative to the victim.

### Recommendation
- Verify the webhook signature using the secret associated with the specific record(s) the handler is about to mutate, not a secret merely inferred from an unauthenticated field of the same payload.
- Have `StatusHandler` (and any other handler) scope lookups through `Repository`/`Stack` derived from a field that was itself part of the org used for signature selection, and reject/ignore statuses whose `sha` maps to a commit belonging to a repository outside the org that authenticated the request.
- Cross-validate that `repository.owner.login` (used to pick the signing secret) is consistent with `repository.full_name`'s owner segment before dispatching to handlers.

### Proof of Concept
1. Multi-org Shipit deployment configured with orgs `attacker-org` (attacker is a member/admin with access to its GitHub App webhook secret) and `victim-org` (unrelated, higher-trust organization tracked by the same Shipit instance).
2. Attacker crafts payload:
```json
{
  "sha": "<victim-org commit sha to be marked green>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac with attacker-org's known webhook_secret>` over the raw body and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `attacker-org` → fetches `attacker-org`'s webhook secret → HMAC matches → request accepted.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matches the victim commit irrespective of org — and calls `create_status_from_github!`, injecting a forged `success` status onto `victim-org`'s commit, potentially satisfying CI gating for deploy.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

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
