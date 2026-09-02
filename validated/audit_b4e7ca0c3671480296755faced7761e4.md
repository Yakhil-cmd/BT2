Confirmed multi-tenant support: `Shipit.github(organization:)` maps each GitHub organization to its own `webhook_secret` via `github_app_config(organization)` [1](#0-0) . The webhook signature is verified against the secret selected for `repository_owner`, but the repository that handlers actually act on is read from a different, unauthenticated-relative-to-that-choice field.

### Title
Cross-Organization Repository Spoofing via Mismatched Webhook Verification Key Selection and Repository Resolution Fields - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment, `Shipit::WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` or falls back to `params.dig('organization', 'login')` [2](#0-1) . Once the signature check passes for that organization's secret, every downstream `Shipit::Webhooks::Handlers::Handler` resolves the target repository/stack from a *different* payload field, `payload.dig('repository', 'full_name')` [3](#0-2) . The signature only proves the payload was signed with organization X's secret; it does not bind or restrict `repository.full_name` to a repository actually owned by organization X.

### Finding Description
This mirrors the referral bug class: the report shows a `referral` address that is *used to route money* but is never included in the value the fee computation trusts/audits — the address is accepted from the caller with no binding to a legitimate party. Here, the analogous equality that should hold is:

`organization whose secret verified the signature == organization/repository the handlers act on`

But the code checks:
- `repository_owner` (`repository.owner.login` / `organization.login`) → selects `GitHubApp` instance and its `webhook_secret` for `verify_webhook_signature` [4](#0-3) .

And separately, handlers use:
- `repository.full_name` → `Repository.from_github_repo_name(repository_name)` to locate stacks to sync/mutate [3](#0-2) , and the same field is required and trusted in `PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `UnlabeledHandler`, etc. [5](#0-4) [6](#0-5) .

Because `verify_webhook_signature` and `repository_owner` never cross-check that `repository.full_name`'s owner matches `repository.owner.login`/`organization.login`, an attacker who legitimately controls a GitHub organization/repository configured in Shipit (and can therefore produce validly-signed webhook deliveries for their own org's secret, e.g., by triggering real GitHub events on their own repo) can craft/replay a payload where `repository.owner.login` (or `organization.login`) names their own org — so the correct, known secret is used and `verify_signature` passes — while `repository.full_name` is set to a stack belonging to a *different* organization/repository tracked by the same Shipit instance. `Repository.from_github_repo_name` and handlers will act on that other repository's stacks (e.g., trigger `GithubSyncJob`, archive/unarchive review stacks, close PRs) even though the signature never certified anything about that other organization or repository.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary called out in scope. A successful exploit lets an attacker with control over one onboarded GitHub organization's webhook delivery pipeline induce state changes (sync, archive/unarchive review stacks, close pull request records) against stacks belonging to a completely different organization/repository within the same Shipit instance — an unauthorized cross-repository write, which meets the Critical bar ("cross-repository writes").

### Likelihood Explanation
Requires: (1) Shipit configured with the multi-tenant `secrets.github` schema (`github_app_config(organization)` present, i.e., more than one organization onboarded) [7](#0-6) , and (2) the attacker controls at least one onboarded organization/repository, from which they can send arbitrary raw webhook bodies signed with that org's own key (a normal capability for an org admin configuring GitHub webhooks, not requiring any Shipit credential). No `ApiClient` token, `webhook_secret` disclosure, or GitHub App key theft is needed — only the attacker's own org's already-known secret. This is a realistic multi-tenant configuration and a plausible attacker who is a legitimate member of one org but not another.

### Recommendation
Bind the field used for repository/stack resolution to the same field used for verification-key selection, and validate consistency explicitly: after selecting `github_app` via `repository_owner`, assert that `repository.full_name` starts with `"#{repository_owner}/"` (case-insensitively) before invoking any handler, rejecting the webhook otherwise. Alternatively, always derive both the verification key and the acted-upon repository from a single canonical, HMAC-covered field.

### Proof of Concept
1. Shipit multi-tenant config has `secrets.github["org-a"]` and `secrets.github["org-b"]`, each with distinct `webhook_secret`, `org-a` under attacker's control.
2. Attacker crafts a `push` payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<victim-sha>",
     "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
   }
   ```
3. Attacker signs it with `org-a`'s known `webhook_secret` and sends `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` [8](#0-7)  — passes, since the signature matches org-a's secret.
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("org-b/victim-repo")` [3](#0-2) [9](#0-8)  and enqueues `GithubSyncJob`/archives review stacks for org-b's repository, despite the signature never certifying anything about org-b.

### Citations

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
