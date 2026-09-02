### Title
Signature verification authenticates the payload's organization, but webhook handlers act on an unrelated repository field within the same payload - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an incoming webhook's HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted JSON body. Once the signature check passes, every webhook handler resolves the `Repository`/`Stack` to act on using a *different* field from that same body: `repository.full_name`. No code enforces that `repository.owner.login` and the owner portion of `repository.full_name` refer to the same organization. This breaks the equality: `organization authenticated by signature == repository written by handler`.

### Finding Description
`verify_signature` picks the app/secret purely from attacker-controlled payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns an organization/App-specific `GithubApp` instance whose `webhook_secret` comes from that organization's own config entry: [3](#0-2) [4](#0-3) 

After the signature check passes, the raw `params` are dispatched unmodified to every registered handler for the event: [5](#0-4) 

All handlers derive the target repository from `repository.full_name`, a completely separate JSON field from the `repository.owner.login`/`organization.login` used for signature selection: [6](#0-5) [7](#0-6) [8](#0-7) 

`Repository.from_github_repo_name` splits `full_name` into owner/name and looks up the matching `Repository`, independent of which org's secret verified the request: [9](#0-8) 

Because HMAC verification is computed over the raw request body, an attacker cannot tamper with a legitimately-signed payload from a victim organization. However, since the *org used for verification* and the *repository used for action* are read from two independent JSON keys in the same body, an attacker who is able to produce a body validly signed by their **own** organization's webhook secret (e.g., they administer their own GitHub organization/App installation connected to this Shipit instance, and thus can set/know that org's `webhook_secret`, or can simply have GitHub deliver a real webhook for their own repo) can set `repository.owner.login`/`organization.login` to their own org (so the correct, known secret is selected and the signature check passes) while setting `repository.full_name` to `"victim-org/victim-repo"`. The signature only proves "this body was signed with attacker-org's secret" — it says nothing about which repository the handler subsequently acts on.

### Impact Explanation
This lets an attacker who controls one legitimately-connected GitHub organization forge cross-repository webhook events (push, pull_request opened/closed/labeled/reopened, membership, etc.) against a completely unrelated, victim-owned Shipit stack/repository. Depending on the handler reached, this can:
- Trigger `GithubSyncJob` / `stack.sync_github` on a victim stack via a forged `push` event (`PushHandler`).
- Create, archive, or unarchive victim review stacks via forged `pull_request` events (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`).
- Mutate victim `PullRequest` records via `AssignedHandler`/`EditedHandler`.

This is a cross-repository write performed without ever holding write access to, or a valid signature scoped to, the victim's repository/organization — matching the Critical impact bucket ("cross-repository writes" / "unauthorized deploy, rollback, or merge" depending on which handler and stack configuration, e.g., continuous deployment, is reached).

### Likelihood Explanation
Requires the attacker to control at least one organization/repository that is legitimately connected to the same Shipit instance (a `webhook_secret` they know), which is a realistic scenario for any Shipit deployment serving multiple orgs/teams. No GitHub App private key, `ApiClient` token, or Shipit session is required — only the ability to produce one validly-signed webhook body for their own org, with attacker-controlled JSON content for the unrelated `full_name` field.

### Recommendation
Bind the organization used for signature verification to the same value used for repository resolution. Concretely: after selecting `repository_owner` and verifying the signature, derive `repository_name` for handler dispatch strictly from the same trusted `repository_owner`, or explicitly re-validate that `repository.full_name.split('/').first == repository_owner` before calling handlers. Alternatively, resolve the target repository/stack using a value that is intrinsically the same field used for signature routing (never two independent JSON keys).

### Proof of Concept
1. Attacker's own GitHub organization `attacker-org` is connected to this Shipit instance, giving the attacker access to (or the ability to legitimately generate) `attacker-org`'s configured `webhook_secret`.
2. Attacker crafts a `push` (or `pull_request`) JSON body where:
   - `repository.owner.login` = `"attacker-org"` (or `organization.login` = `"attacker-org"`)
   - `repository.full_name` = `"victim-org/victim-repo"`
   - other required fields (`ref`, `after`, etc.) filled in to target the victim stack's tracked branch.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org's webhook_secret, raw_body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')`, verifies against the correct, attacker-known secret → passes.
5. `Shipit::Webhooks.for_event('push').each { |h| h.call(params) }` → `PushHandler#stacks` resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and triggers `stack.sync_github` (or archives/creates a review stack, depending on handler) on the victim's repository, despite the request never being signed by anything associated with `victim-org`.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
