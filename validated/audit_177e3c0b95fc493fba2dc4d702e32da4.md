### Title
Webhook signature is verified against the organization derived from the payload body while events are dispatched using a different, unverified field from the same body - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multi-organization GitHub App configuration, each organization having its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed from the unverified JSON body itself (`repository.owner.login`, falling back to `organization.login`) [2](#0-1) . However, once the signature check passes, the actual event handlers resolve the target repository/stack using a *different* field of the same unverified body: `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing enforces that `repository.owner.login` (used to pick the signing secret) and the owner embedded in `repository.full_name` (used to select the Repository/Stack to act on) refer to the same organization.

### Finding Description
This mirrors the reported bug class exactly: a guard condition (duplicate/eligibility check keyed on an address) is bypassed because a different, unchecked value (the zero address) is used for the actual state-changing operation. Here, the "guard" is signature verification, keyed off `repository_owner`:

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end
``` [2](#0-1) 

The state-changing operation (looking up the repository/stack that a handler will act on) uses a sibling field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

Because both `repository.owner.login` and `repository.full_name` are attacker-controlled JSON fields inside the raw POST body over which the HMAC is computed, an attacker who legitimately controls (or is a member of) *one* onboarded organization "Org A" (and thus knows/can compute a valid signature using Org A's `webhook_secret`) can craft a payload where:
- `repository.owner.login` = `"org-a"` (or `organization.login` = `"org-a"`) — causing `verify_signature` to select Org A's `webhook_secret` and succeed, since the attacker can compute a correct HMAC with that secret.
- `repository.full_name` = `"org-b/some-repo"` — a completely different, victim organization's repository that the attacker does not control.

The signature check would pass (it only proves the payload was signed with *some* configured organization's secret — not that the *acted-upon* repository belongs to that organization), yet the handler processing the event would resolve and act on Org B's repository/stacks using `Repository.from_github_repo_name("org-b/some-repo")` [4](#0-3) .

Equality being broken:
`organization authenticated by verify_signature (repository_owner)` ≠ `organization of the repository actually written to (repository.full_name)`.

### Impact Explanation
Depending on which webhook event type is forged, this can drive unauthorized state changes on a target stack belonging to an organization the attacker does not control, using only the credentials (webhook secret) of an organization they *do* control. Handlers using `stacks`/`repository_name` include pull_request handlers (opened/closed/labeled/etc.) which create/update `ReviewStack`s, set labels-driven provisioning behavior, and mutate pull request state for the targeted repository [5](#0-4) , and the `push`/`status`/`check_suite` handlers that trigger `GithubSyncJob`/status updates against the resolved stack [6](#0-5) . This can result in cross-repository writes (unauthorized stack/review-stack creation, mutation, or continuous-deployment triggering) on repositories the attacker was never granted access to — satisfying the "cross-repository writes" / "unauthorized deploy" Critical impact criteria, since it breaks the binding between "organization whose secret authenticated the webhook" and "repository/stack actually mutated."

### Likelihood Explanation
This requires the deployment to be configured with the multi-organization GitHub config schema (multiple `github.<org>.webhook_secret` entries) as described in `Shipit.github_app_config`/`github_organizations` [7](#0-6) , and for the attacker to already be onboarded as a legitimate organization in that Shipit instance (i.e., possess or be able to trigger genuine webhook deliveries signed with their own org's secret, which any org admin can do via GitHub App webhook redelivery or a custom endpoint replay, or simply crafting the raw HTTP POST directly to Shipit with a correctly computed HMAC using their own known secret — no GitHub involvement required since Shipit only checks the HMAC against the raw body, not that GitHub actually sent it for that repo). This is a realistic scenario for any Shipit instance onboarding multiple independent organizations/tenants.

### Recommendation
After selecting the signing GitHub App by `repository_owner`, verify that the resolved repository/stack referenced by `repository.full_name` (or `organization.login`) actually belongs to the *same* organization used to select the webhook secret — reject the webhook (422) if `repository.full_name.split('/').first` (case-insensitively) does not match `repository_owner`/the organization used for `Shipit.github(organization:)`. This closes the gap analogous to requiring `registerProposal`/`refund` to reject the zero address by requiring the authenticating field and the acted-upon field to agree.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with a distinct `webhook_secret` (multi-org schema) per `docs/setup.md`/`lib/shipit.rb`.
2. As a member/owner of `org-a`'s GitHub App installation (or simply knowing `org-a`'s configured `webhook_secret`), craft a `pull_request` (or `push`) webhook JSON payload where:
   - `organization.login` / `repository.owner.login` = `"org-a"`
   - `repository.full_name` = `"org-b/victim-repo"` (a repository/stack that exists under `org-b`, unrelated to the attacker)
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(org_a_webhook_secret, raw_body)>` and POST to `/webhooks`.
4. `WebhooksController#verify_signature` selects `Shipit.github(organization: 'org-a')`, verifies the signature successfully (matches).
5. The matched handler (e.g., pull_request `OpenedHandler`) calls `stacks` → `Repository.from_github_repo_name('org-b/victim-repo')` [3](#0-2) [4](#0-3) , resolving and mutating `org-b`'s repository/stacks despite the request only having been authenticated as belonging to `org-a`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L1-20)
```ruby
# frozen_string_literal: true

module Shipit
  class GithubSyncJob < BackgroundJob
    include BackgroundJob::Unique

    attr_reader :stack

    MAX_FETCHED_COMMITS = 25
    MAX_RETRY_ATTEMPTS = 5
    RETRY_DELAY = 5.seconds
    queue_as :default
    on_duplicate :drop

    self.timeout = 60
    self.lock_timeout = 20

    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
```
