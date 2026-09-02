### Title
Cross-Repository Commit Status Forgery via Organization/Repository Binding Mismatch in Webhook Signature Verification - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate an inbound webhook's HMAC signature against by reading the **unverified** JSON body (`repository.owner.login` or `organization.login`), *before* the signature itself is checked. In a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration in `docs/setup.md` "Using Multiple Github Applications"), each org has its own `webhook_secret`. Because the org used to pick the secret is attacker-controlled and is never cross-checked against the data the webhook handlers actually act on, a party who legitimately possesses the `webhook_secret` for one onboarded organization can forge a validly-signed webhook whose payload targets resources belonging to a **different** organization/stack in the same Shipit instance.

### Finding Description
`verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`repository_owner` is read straight from the untrusted `request.raw_post` (parsed later into `params` for handler dispatch too) — the same JSON body whose authenticity the signature check is supposed to establish. `Shipit.github(organization:)` then looks up the org-specific `webhook_secret` from `secrets.github[<org>]` [2](#0-1) . Once `verify_webhook_signature` succeeds (which it will, if the attacker used the secret of *any* org they legitimately administer), the raw body is dispatched unchanged to event handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers never re-validate that the payload's target (repository/commit) actually belongs to the organization whose secret authenticated the request:

- `StatusHandler` looks up commits **globally by SHA**, with no repository/organization scoping at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 
Since commit SHAs are effectively global identifiers shared across the whole Shipit instance's database, an attacker who knows (or can guess/observe) the SHA of a commit belonging to a *different* org's tracked stack can inject a fake `state: "success"` status for it while authenticating with their own org's webhook secret.

- Other handlers (`PushHandler`, `CheckSuiteHandler`, `PullRequest::OpenedHandler`, etc.) scope to a Stack via `payload.dig('repository', 'full_name')` [5](#0-4) , which is a *separate, independent* field from the `repository.owner.login`/`organization.login` field used for secret selection. Nothing enforces that these two fields refer to the same organization, so an attacker can sign with their own org's secret while setting `repository.full_name` to point at a victim org's tracked repository, triggering `stack.sync_github(expected_head_sha:)` [6](#0-5)  or check-run refreshes on a stack the attacker does not control.

The broken trust binding, expressed as an equality that should hold but doesn't: **organization whose `webhook_secret` authenticated the request == organization/repository whose Stack/Commit data is mutated by the handler**. This is the direct analog of the reported bug class: a field used for a security decision (order lock eligibility / here, secret selection) is not the same field the effect is actually computed against (`order_vault` balance / here, the commit or stack that gets written), and no invariant ties them together.

### Impact Explanation
A `Status` record created via `create_status_from_github!` triggers `after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery` [7](#0-6) . If the victim stack has continuous deployment enabled, a forged `success` status for one of its commits can cause an **unauthorized deploy** of that commit — impersonating the victim organization's CI without ever knowing the victim's own `webhook_secret`. This matches the Critical-tier impact category ("an unauthorized deploy, rollback, or merge") because it crosses an organizational/credential trust boundary that is supposed to isolate tenants of a multi-organization Shipit deployment.

### Likelihood Explanation
Exploitation requires: (1) the Shipit instance configured with more than one GitHub organization (`Shipit.github_organizations`), a documented supported feature; (2) the attacker legitimately controls (as an org admin/owner) at least one of the configured organizations and thus knows its `webhook_secret`; (3) knowledge of a target commit SHA in the victim's repository (commit SHAs are often disclosed publicly through PRs, CI links, or the public GitHub repo itself). Given multi-tenant Shipit setups are explicitly documented as a first-class use case, and no additional secret is required beyond one the attacker already legitimately possesses, this is a realistic, low-effort attack for anyone onboarding a second, less-trusted organization into a shared Shipit instance.

### Recommendation
1. Verify the webhook signature using the organization actually associated with the resolved target (Stack/Repository) rather than an attacker-controlled field from the unverified body — or, if verifying by payload-declared org is unavoidable, re-check after verification that every organization-identifying field in the payload (`repository.owner.login`, `organization.login`, `repository.full_name`'s owner segment) is consistent with each other and with the organization whose secret validated the signature.
2. Scope `StatusHandler` (and any handler that looks up records without going through `Handler#stacks`) to the repository/organization derived from the verified webhook context, not a global `Commit.where(sha: ...)` lookup.
3. Reject webhooks where the declared repository owner does not match the organization whose secret validated the signature.

### Proof of Concept
Preconditions: Shipit configured with two organizations, `orgA` (attacker-administered) and `orgB` (victim, tracked separately in the same Shipit instance), per `docs/setup.md`'s multi-org config.

1. Attacker obtains `orgA`'s `webhook_secret` (they are the admin who installed/configured `orgA`'s GitHub App).
2. Attacker learns the SHA of a commit tracked under `orgB`'s stack (e.g., from a public PR or CI badge).
3. Attacker crafts a `status` event payload:
```json
{
  "sha": "<orgB-victim-commit-sha>",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "orgA" } }
}
```
4. Attacker computes `X-Hub-Signature` using `orgA`'s known `webhook_secret` over the raw body and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: "orgA")`, verification succeeds using the attacker's own secret. [8](#0-7) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (unscoped by org), and creates a forged `success` status for it. [4](#0-3) 
7. If `orgB`'s stack has continuous deployment enabled, this triggers an unauthorized deploy of that commit.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
