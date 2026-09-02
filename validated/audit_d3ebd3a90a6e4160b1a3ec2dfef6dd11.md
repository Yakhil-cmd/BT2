### Title
`no-secret organization` webhook bypass lets an attacker provision a fork-controlled review stack - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when `@webhook_secret` is blank, so any organization configured in Shipit without a `webhook_secret` accepts unsigned/forged webhooks. Combined with `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler`, an attacker can forge a `pull_request` `opened` event naming that organization and cause Shipit to create a `ReviewStack`/`Stack` whose `branch` is taken directly from the attacker-controlled `pull_request.head.ref`.

### Finding Description
The broken binding: `verified == (HMAC(webhook_secret, raw_body) matches X-Hub-Signature)` is expected to hold for every accepted webhook, but in `GitHubApp#verify_webhook_signature` the code short-circuits: `return true unless webhook_secret` [1](#0-0) . When an org's config in `Shipit.secrets.github` has no `webhook_secret` key, `@webhook_secret` is `nil` (set from `@config[:webhook_secret].presence`) [2](#0-1) , so `verify_webhook_signature` returns `true` for *any* body/signature pair, regardless of whether the request actually originated from GitHub.

`WebhooksController#verify_signature` resolves the `GitHubApp` instance purely from attacker-controlled JSON: `repository_owner` reads `params.dig('repository', 'owner', 'login')` [3](#0-2)  and feeds it into `Shipit.github(organization: repository_owner)` before calling `verify_webhook_signature` [4](#0-3) . If that org exists in config with no secret, `verified` is `true` and the request proceeds to `create`, which dispatches to `Shipit::Webhooks.for_event(event)` handlers with the raw, unauthenticated JSON [5](#0-4) .

For a `pull_request` event with `action: "opened"`, `OpenedHandler#process` looks up the `Repository` by `params.repository.full_name` and, if `review_stacks_enabled` and the provisioning policy permits it, calls `ReviewStackAdapter#find_or_create!` [6](#0-5) . `ReviewStackAdapter#create!` builds the new `Stack`/`ReviewStack` with `branch: params.pull_request.head.ref` — entirely attacker-supplied — and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)` [7](#0-6) . This is a real state mutation (`Shipit::Stack` row + provisioning-queue entry) attributed to a tracked repository, triggered by a request that never passed real signature verification.

Existing guards do not stop this: `drop_unhandled_event` only filters unknown event types, not unauthenticated ones [8](#0-7) ; `GithubOrganizationUnknown` only fires when the org is *not* configured at all [9](#0-8) , which is the opposite of this precondition (org *is* configured, just missing a secret); the `ExplicitParameters` schema on `OpenedHandler` validates payload shape but not provenance [10](#0-9) .

### Impact Explanation
An attacker who can send arbitrary HTTP requests to `POST /webhooks` (no session, no token) can, for any organization/repository whose Shipit config lacks a `webhook_secret`, create arbitrary `pr<N>` review stacks pointing at a fork-controlled branch (`head.ref`) for a repository they do not own. If that repository/stack is subsequently provisioned/deployed by Shipit's CD pipeline, attacker-controlled code from the named branch can be built/deployed — an unauthorized deploy of attacker content. This is repeatable per PR number/org and scoped to whichever tracked repositories fall under the no-secret organization; it matches the "payload for one repository mutating another's stack" / "unauthorized deploy" Critical impact category, though the blast radius is bounded to organizations that are actually misconfigured without a `webhook_secret`.

### Likelihood Explanation
Exploitability strictly requires an operator-side misconfiguration: an organization entry present in `Shipit.secrets.github` (so `github_app_config` resolves) but with a blank/absent `webhook_secret` key. If every configured organization sets a `webhook_secret` (the documented/expected setup), this path is unreachable — `verify_webhook_signature` behaves correctly. Given that precondition, attacker cost is trivial: one unauthenticated HTTP POST with a crafted JSON body naming the org and an existing/tracked `repository.full_name`, no valid `X-Hub-Signature` needed, fully repeatable.

### Recommendation
Fail closed instead of open when no `webhook_secret` is configured for an organization: reject the request (or require an explicit opt-in flag) instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`. At minimum, log/alert loudly and refuse to process state-mutating webhook events (`pull_request`, `push`, etc.) for organizations lacking a configured secret.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Stub `Shipit.secrets.github` (or the relevant `github_app_config`) so organization `"forkorg"` is configured with `app_id`/`installation_id`/`private_key` but **no** `webhook_secret`.
2. Ensure a tracked `Shipit::Repository` exists (`forkorg/target-repo`) with `review_stacks_enabled = true` and `provisioning_behavior = :allow_all`.
3. `POST /webhooks` with header `X-Github-Event: pull_request`, **no** `X-Hub-Signature` header (or a garbage one), and body:
   ```json
   { "action": "opened", "number": 999,
     "pull_request": { "id":1, "number":999, "url":"u", "title":"t", "state":"open",
       "additions":1, "deletions":0,
       "head": { "sha":"deadbeef", "ref": "attacker/fork-branch" },
       "user": {"login":"attacker"}, "assignees": [], "labels": [] },
     "repository": { "full_name": "forkorg/target-repo", "owner": { "login": "forkorg" } },
     "sender": { "login": "attacker" } }
   ```
4. Assertions on both sides of the binding:
   - Before: `Shipit::Stack.where(environment: "pr999").exists?` is `false`.
   - `assert_response :ok` (not `:unprocessable_entity`), proving `verify_signature` accepted the unsigned body.
   - After: `assert_difference -> { Shipit::Stack.count }` — a new `Stack` exists with `branch == "attacker/fork-branch"` and `environment == "pr999"`, and it is present in `Shipit::ReviewStackProvisioningQueue`.
   - Contrast test: same payload but organization configured *with* a `webhook_secret` and no valid signature → `assert_response :unprocessable_entity`, no `Stack` created — demonstrating the divergence is caused solely by the blank `webhook_secret`.

### Citations

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** lib/shipit.rb (L170-181)
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
```
