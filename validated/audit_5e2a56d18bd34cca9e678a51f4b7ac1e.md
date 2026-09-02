This confirms the vulnerability mechanism. Let me verify the multi-org config parsing (`github_app_config`) to confirm attacker-controlled `repository_owner` selects which secret is used for verification independently of which field the handler uses to select the target stack/repository.### Title
Webhook signature verification keys off an attacker-controlled `repository.owner.login` field that is decoupled from the `repository.full_name` field actually used to select the target Stack/Repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` chooses which GitHub App/organization secret to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the untrusted, attacker-supplied JSON body, *before* the signature has been checked. [1](#0-0)  Once the signature check passes for whichever organization happened to be named in that field, every event handler (`PushHandler`, `StatusHandler`'s siblings, `PullRequest::*Handler`, etc.) derives the actual write target from a *different* field, `repository.full_name`, via `Handler#repository_name`/`Repository.from_github_repo_name`. [2](#0-1)  Because `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled keys inside the same JSON object, the organization whose secret authenticated the request is not bound to the repository whose stack gets mutated.

### Finding Description
This is the same class of bug as the LibSwap report: a value that is checked/verified (`fromAmount` pulled based on `initialSendingAssetBalance`) is not the same value that is actually acted upon later, letting an attacker substitute a different value for the one that was actually verified.

Concretely:
- `Shipit.github(organization: ...)` looks up a per-organization `GitHubApp` (and its `webhook_secret`) from `Rails.application.credentials.github`, supporting a config where each GitHub organization has its own, independently configured `webhook_secret` (optionally blank per the shipped example config). [3](#0-2) [4](#0-3) 
- `WebhooksController#verify_signature` selects that org purely from the JSON payload (`repository_owner`) and verifies the raw body against *that* org's secret: `github_app = Shipit.github(organization: repository_owner); verified = github_app.verify_webhook_signature(...)`. [5](#0-4) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally if that organization's `webhook_secret` is blank/unset: `return true unless webhook_secret`. [6](#0-5) 
- Every downstream handler ignores `repository.owner.login` entirely and instead resolves the affected `Repository`/`Stack` using `repository.full_name` (`Repository.from_github_repo_name`), a completely separate field of the same attacker-supplied JSON body. [2](#0-1) [7](#0-6) 

The binding that should hold is:
`organization authenticated by verify_signature == organization that owns the repository being written to by the handler`

but the code never enforces `repository.owner.login == repository.full_name.split('/').first`. An attacker can pick, as `repository.owner.login`, any organization configured in `Shipit.secrets.github` whose `webhook_secret` happens to be unset/blank (this is explicitly documented as "optional" in the setup docs and the example secrets file ships with `webhook_secret: # nil`) [8](#0-7) , causing signature verification to trivially pass, while setting `repository.full_name` to `victim-org/victim-repo` for a *different*, fully protected organization/stack that Shipit also manages.

### Impact Explanation
This breaks the "organization authenticated versus the repository that is written" trust binding called out in scope. In a multi-organization Shipit deployment (a first-class, documented configuration — see `secrets.development.example.yml`'s multi-org schema) [4](#0-3) , if even one configured organization lacks a `webhook_secret` (the documented default/optional state), an unauthenticated, unprivileged attacker can:
- Force `PushHandler` to call `stack.sync_github(expected_head_sha: ...)` on any stack belonging to a *different, fully secured* organization, forging the deployed/undeployed commit state Shipit uses to gate deploys. [9](#0-8) 
- Force `StatusHandler` to write forged CI/commit statuses (`create_status_from_github!`) against commits in a victim repository, since `StatusHandler` doesn't scope by repository/owner at all and simply matches on `sha`. [10](#0-9) 
- Force PR handlers (`opened_handler`, `closed_handler`, `labeled_handler`) to archive/unarchive/create review stacks or capture labels on a victim organization's review stacks, all keyed off the independently-controlled `repository.full_name`. [11](#0-10) [12](#0-11) 

Since forged/spoofed commit statuses and forged sync state can influence whether Shipit considers a commit deployable/CI-green and can affect continuous-deployment triggering, this crosses into unauthorized-write / unauthorized-deploy-adjacent territory across repository/organization boundaries without possessing any org's actual `webhook_secret`.

### Likelihood Explanation
Likelihood is moderate-to-high in any multi-org Shipit install:
- No credential is required for the attacker-chosen organization if its `webhook_secret` is unset (the documented default and example config).
- The attacker only needs the target victim's `owner/name` (public information, since GitHub repo names are typically known/public) to populate `repository.full_name`.
- No GitHub App installation, OAuth token, or `ApiClient` token is needed — this is a plain unauthenticated POST to `/webhooks`, which is explicitly `skip_before_action :verify_authenticity_token` and otherwise open. [13](#0-12) 

### Recommendation
Bind the field used for signature-secret selection to the field used for repository resolution:
- In `WebhooksController#verify_signature`, after selecting the organization and verifying the signature, additionally assert that `params.dig('repository','full_name')&.split('/')&.first&.casecmp?(repository_owner)` (and equivalently for `organization.login`-based events), rejecting (422) on mismatch.
- Alternatively, make `Handler#repository_name`/`stacks` resolution use the *verified* organization (already known to the controller) rather than trusting `repository.full_name` outright, or re-validate that the resolved `Repository#owner` matches the organization whose secret was used to verify the request.
- Consider disallowing organizations with a blank `webhook_secret` in any config where more than one organization is configured, since a blank secret in a multi-tenant setup effectively becomes a skeleton key for spoofing events attributed to that org.

### Proof of Concept
Preconditions: Shipit configured with two GitHub organizations in `Rails.application.credentials.github`: `weak-org` (no `webhook_secret` configured) and `victim-org/victim-repo` (has a stack in Shipit, webhook_secret configured and kept secret).

1. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "weak-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No `X-Hub-Signature` header needs to be valid HMAC for anything, because:
```ruby
github_app = Shipit.github(organization: "weak-org")   # repository_owner from payload
verified = github_app.verify_webhook_signature(sig, body)  # returns true, webhook_secret blank
```
(`app/controllers/shipit/webhooks_controller.rb:25-30`, `lib/shipit/github_app.rb:76-83`).

2. Signature check passes, `WebhooksController#create` dispatches to `PushHandler`, which computes `repository_name` from `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, looks up that `Repository`'s stacks, and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the *victim's* stack — despite the request never having been authenticated by anything belonging to `victim-org`. [9](#0-8) [2](#0-1) 

**Uncertainty**: I could not fully trace every downstream side effect of `sync_github`/`create_status_from_github!` in this pass (e.g., whether `sync_github` alone can force an actual deploy or only updates cached commit/branch state) since those files were not opened in this investigation; a full exploit chain to an "unauthorized deploy" would need to confirm what `Stack#sync_github` does with a forged `expected_head_sha` and whether continuous deployment could be triggered as a result. I recommend a Devin session with full repo access to trace `Stack#sync_github`, `Commit#create_status_from_github!`, and `ContinuousDeliveryJob` to confirm the maximal impact of this specific cross-organization write.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-15)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
