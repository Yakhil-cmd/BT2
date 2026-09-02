### Title
Webhook signature is verified against the organization/app named in `repository.owner.login`, but the event is dispatched using `repository.full_name` — allowing a valid signature from one configured GitHub organization to authorize writes against a repository under a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit` supports multiple GitHub App configurations, one per organization, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the incoming signature against based on `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` [2](#0-1) . Once the signature is accepted, the entire raw, attacker-controlled `params` hash is forwarded unmodified to every registered handler for the event [3](#0-2) . Handlers, however, do not use `repository.owner.login` to resolve the target — they use a completely separate field, `repository.full_name`, both in the base `Handler` class (`stacks`/`repository_name`) and in the `PushHandler` (via `stacks`) and every `pull_request` handler (via `Repository.from_github_repo_name(params.repository.full_name)`) [4](#0-3) [5](#0-4) [6](#0-5) .

### Finding Description
The trust binding that should hold is: *the GitHub organization whose secret authenticated the request* == *the repository/organization whose state the handler mutates*. This engine breaks that equality.

- Before the pull request: nothing changes this comparison; multi-tenant `secrets.github` configs each carry an independent `webhook_secret` per organization key, looked up via `Shipit.github(organization:)` [1](#0-0) .
- After crafting the payload: an attacker who legitimately controls (or has installed the Shipit-integrated GitHub App on) one configured organization — call it `attacker-org` — knows `attacker-org`'s `webhook_secret` and can compute a correct `X-Hub-Signature` for any payload of their choosing, since HMAC verification only checks payload bytes against the secret for the org named in `repository.owner.login` [7](#0-6) .
- The attacker sets `repository.owner.login = "attacker-org"` (so `verify_signature` selects and validates against the secret they know) while setting `repository.full_name = "victim-org/victim-repo"` in the same JSON body. `verify_signature` never checks that these two fields agree [2](#0-1) .
- The signature check passes, and `create` hands the full unmodified payload to handlers, which resolve the target stack purely from `full_name` via `Repository.from_github_repo_name` [8](#0-7) , operating on `victim-org/victim-repo` despite the request only being authenticated for `attacker-org`.

This is exactly the class of bug described in the source report: a value that is computed/verified under one binding (protocol fee minted alongside swap amount but never reconciled against what's actually consumed) diverges from the value actually acted upon — here, the organization whose secret validated the signature diverges from the organization/repository actually mutated. For `push` events this triggers `stack.sync_github(expected_head_sha:)` [9](#0-8) , i.e. an unauthorized-org actor can trigger a GitHub sync (and thus deploy queue population) job against a stack that belongs to an organization they were never authenticated for.

### Impact Explanation
This crosses an authentication boundary defined by the rules: it is an "organization that authenticated versus the repository that is written" mismatch. Concretely, it lets an actor who only controls one tenant's webhook secret inject events (e.g. push notifications driving `GithubSyncJob`) that are processed as if they came from a different tenant's repository, without ever possessing that tenant's secret. This matches the High-impact category ("escalation ... unauthenticated read of stack state ... or forced processing") since the request is never actually authenticated for the target repository/stack yet is fully processed as if it were.

### Likelihood Explanation
Requires the attacker to be a legitimate installer/owner of at least one GitHub organization configured in the same multi-tenant Shipit instance (i.e., not a privileged Shipit user or GitHub App holder for the *victim* org) — this is plausible in any shared/multi-org Shipit deployment, which is an explicitly supported configuration (`TOP_LEVEL_GH_KEYS`, `github_app_config`) [10](#0-9) [11](#0-10) . No GitHub App private key, `ApiClient` token, or Shipit session is needed — only knowledge of one tenant's `webhook_secret`, which such a tenant legitimately possesses.

### Recommendation
In `WebhooksController#verify_signature`, after selecting the app config by `repository_owner`, also verify that `repository_owner` matches the owner encoded in `repository.full_name` (and, more robustly, resolve the target `Repository`/`Stack` via `Repository.from_github_repo_name` and confirm its `owner` equals the authenticating organization) before dispatching to handlers. Reject the webhook (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `attacker-org` (secret known to attacker, e.g. because they installed the app on their own org) and `victim-org` (hosts `victim-org/victim-repo`, a real Shipit stack).
2. Attacker computes `sha1=HMAC(attacker-org secret, body)` for a push payload where:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `ref = "refs/heads/master"`, `after = <arbitrary sha>`
3. POST to `/webhooks` with `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully [12](#0-11) .
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` [9](#0-8) , acting on `victim-org`'s stack despite authentication only being valid for `attacker-org`.

*Note: I could not fully trace every downstream handler's exposure (e.g., whether `sync_github` alone allows further state corruption beyond triggering a sync job) due to index/time constraints; a Devin session with full repo access would be needed to enumerate the complete blast radius across all handler types (`status`, `check_suite`, `membership`, `pull_request`).*

### Citations

**File:** lib/shipit.rb (L63-63)
```ruby
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
