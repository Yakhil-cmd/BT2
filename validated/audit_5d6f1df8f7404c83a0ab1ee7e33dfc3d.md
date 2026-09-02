Confirmed: `Shipit.github(organization:)` supports multiple independently-configured GitHub organizations, each with its own `webhook_secret` in `secrets.github` (per `lib/shipit.rb:170-200`, `github_app_config`). This confirms the multi-tenant setup where the webhook signature check binds to one org's secret, while the actual write target (`Repository.from_github_repo_name`) is resolved from a payload field that isn't cryptographically tied to that same org.

### Title
Webhook signature is verified against the `repository.owner.login` organization while writes are performed against the unrelated `repository.full_name` field, allowing cross-tenant event forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook using the GitHub App/`webhook_secret` configured for the organization named in `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). However, every webhook handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, PR handlers, etc.) resolves the actual `Stack`/`Repository`/`Commit` records to mutate using a completely different payload field: `payload.dig('repository', 'full_name')` via `Handler#repository_name` / `Repository.from_github_repo_name`. Because both fields live in the same attacker-controlled, not-yet-verified JSON body, an attacker who legitimately controls one tenant organization's `webhook_secret` can forge a signature that Shipit accepts, while pointing `repository.full_name` at a completely unrelated organization's repository hosted on the same shared Shipit instance.

### Finding Description
The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization owning the repository being written to`

In `verify_signature`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` looks up a per-organization config (including a distinct `webhook_secret`) keyed by `github_organization = organization.downcase.to_sym` from `secrets.github`: [2](#0-1) 

But every handler determines *what to mutate* from an entirely separate field of the same unverified JSON body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`Repository.from_github_repo_name` performs a global, non-org-scoped lookup, so it can match a repository belonging to any tenant configured on the instance, not just the organization used for signature verification.

Before the attacker's request: `repository.owner.login == "attacker-org"` and `repository.full_name == "attacker-org/some-repo"` would be the only valid combination that GitHub itself would ever send for a real `attacker-org` webhook.

After the attacker's crafted request: the attacker (who legitimately owns/administers `attacker-org`'s GitHub App installation and therefore knows `attacker-org`'s `webhook_secret`, per `docs/setup.md`) can freely choose the JSON body, setting `repository.owner.login = "attacker-org"` (so `verify_signature` uses their own known secret and passes) while setting `repository.full_name = "victim-org/victim-repo"` (so the handler mutates the victim tenant's data). The two fields never have to agree.

### Impact Explanation
This breaks the authentication boundary between tenants on a shared Shipit instance. Concretely, an attacker controlling only their own org's webhook secret can:
- Forge `status` events to inject fabricated commit statuses on a victim repository's commits via `StatusHandler#process` / `Commit#create_status_from_github!`, which can flip a commit's deployability and unblock CI-gated deploys/merges for a repo the attacker has no access to [4](#0-3) [5](#0-4) .
- Forge `push` events causing `GithubSyncJob` to run against the victim stack with an attacker-chosen `expected_head_sha` [6](#0-5) .
- Trigger membership/PR/check_suite side effects against victim repositories similarly.

This constitutes an unauthorized cross-repository/cross-tenant write, matching the "Critical: cross-repository writes" impact bucket, since the attacker never had any credential or permission scoped to the victim organization/repository.

### Likelihood Explanation
Exploitability only requires the attacker to be a legitimate customer/administrator of *any one* organization onboarded to the same shared Shipit deployment (a routine, low-privilege scenario for a multi-tenant Shipit install, as documented in `docs/setup.md`'s per-organization `webhook_secret` setup). No Shipit session, `ApiClient` token, or GitHub App private key of the victim's org is required — only the attacker's own webhook secret, which they legitimately possess. This makes the attack straightforward for anyone administering a co-tenant organization.

### Recommendation
Cross-check that the organization used to verify the signature is the same organization implied by `repository.full_name` (i.e., `repository.full_name.split('/').first` must case-insensitively equal `repository_owner`) before dispatching to handlers, and reject the webhook otherwise. More robustly, scope `Repository.from_github_repo_name` lookups (or the handler dispatch) to the verified organization rather than trusting an independent, unauthenticated payload field.

### Proof of Concept
1. Shipit is configured for two tenants in `secrets.github`: `attacker-org` (secret known to the attacker who administers it) and `victim-org` (a separate repository/stack hosted on the same Shipit instance).
2. Attacker crafts a `status` webhook body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw JSON body and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and the signature matches, so the request passes [7](#0-6) .
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` (a global, cross-tenant query) belonging to `victim-org/victim-repo`'s stack and creates a forged successful status on it [8](#0-7) , potentially unblocking deploys that are gated on that CI context — all without ever knowing `victim-org`'s webhook secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
      end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```
