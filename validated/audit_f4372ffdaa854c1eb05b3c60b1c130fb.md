### Title
Cross-organization webhook forgery: signature verification org is decoupled from the repository/stack the handler mutates - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` used for HMAC verification from `repository_owner`, which is read straight out of the attacker-supplied JSON body (`repository.owner.login` or, as fallback, `organization.login`). The event handlers (e.g. `PushHandler`) resolve which `Stack`/`Repository` to mutate from a *different*, independently attacker-controlled field: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so if any one configured GitHub organization in `Shipit.github` has no `webhook_secret` set, an attacker can use that organization's name to skip signature verification entirely while pointing `repository.full_name` at an arbitrary, unrelated, already-onboarded repository/stack, causing `Stack#sync_github` to run for it.

### Finding Description
The claimed binding, stated as an equality, is: `verifying_org == mutated_repo_owner`, where
- `verifying_org` = the organization whose `GitHubApp#webhook_secret` is used to validate `X-Hub-Signature` in `verify_signature`, computed as: [1](#0-0) [2](#0-1) 
- `mutated_repo_owner` = the owner of the `Repository` resolved for the event handler, computed from a completely separate field of the same JSON body: [3](#0-2) [4](#0-3) 

Tracing the request: with `repository.owner.login = 'org-with-no-secret'` and `repository.full_name = 'victim-org/private-repo'`, `repository_owner` resolves to `'org-with-no-secret'`. `Shipit.github(organization: 'org-with-no-secret')` returns a `GitHubApp` whose `@webhook_secret` is `nil` (per `GitHubApp#initialize`, `@webhook_secret = @config[:webhook_secret].presence`): [5](#0-4) 
`verify_webhook_signature` then short-circuits and returns `true` without touching `X-Hub-Signature` at all: [6](#0-5) 
Verification passes with no signature check performed. `WebhooksController#create` then dispatches to `Shipit::Webhooks.for_event('push')`, which invokes `PushHandler.call(params)`: [7](#0-6) 
`PushHandler#process` resolves `stacks` via `Handler#stacks`/`#repository_name`, which reads `payload.dig('repository', 'full_name')` — i.e. `'victim-org/private-repo'`, unrelated to the `'org-with-no-secret'` value used above — and calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on that branch: [8](#0-7) 
`Stack#sync_github` enqueues `GithubSyncJob`, which fetches commits from GitHub and appends them to the victim stack's commit history/spec cache: [9](#0-8) 

Before: verification is expected to bind to the same repository/org being mutated. After tracing: `verifying_org = 'org-with-no-secret'` while `mutated_repo_owner = 'victim-org'` — the equality is false, and no code anywhere checks that `repository_owner` (used to pick the verifying `GitHubApp`) matches the owner embedded in `repository.full_name` (used to pick the mutated `Repository`/`Stack`). `drop_unhandled_event`, the `ExplicitParameters` schema for `PushHandler` (`requires :ref` / `requires :after` only), and `Repository.from_github_repo_name` (plain string split, no cross-check against payload owner) do not prevent this divergence.

### Impact Explanation
Given the stated precondition (one configured GitHub organization in `Shipit.github` with no `webhook_secret`), an attacker with no Shipit credentials can forge a `push` webhook that causes `Stack#sync_github` to run for any already-onboarded repository/stack in the Shipit instance, regardless of which organization actually owns that repository or whether that organization's own `webhook_secret` is properly configured. This is a payload nominally scoped to one organization mutating another organization's/repository's stack state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any stack/branch combination already registered in Shipit, and each POST can trigger a fresh sync/commit ingestion cycle.

### Likelihood Explanation
Exploitability depends entirely on Shipit's multi-org `github:` configuration containing at least one organization entry with a blank/missing `webhook_secret` (shown as the default/unset value in `config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml`, and other sample configs) alongside other organizations whose repositories the attacker wants to target. This is a plausible operational misconfiguration in multi-tenant Shipit deployments (e.g., an org added but not yet given a webhook secret) rather than a default single-org production setup where `webhook_secret` is documented as required. No attacker secrets, sessions, or GitHub privileges are needed — only knowledge (or brute-force guessing) of an underconfigured org name that is registered in `Shipit.github` and the target repo's `full_name`.

### Recommendation
Bind signature verification to the same repository the handler will act on: derive the verifying organization from `repository.full_name`'s owner segment (or require it to match `repository.owner.login`/`organization.login`) rather than trusting `repository_owner` independently, and reject the request if the two disagree. Additionally, treat a missing `webhook_secret` as a hard configuration error (refuse to boot, or reject all webhooks for that org) rather than silently returning `true` from `verify_webhook_signature`.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` style (no live GitHub calls, `GithubSyncJob` enqueue asserted):
1. Configure `Shipit.stubs(:secrets).returns(...)` or use fixture config with two orgs: `org-with-no-secret` (no `webhook_secret`) and the org owning `victim-org/private-repo`'s Shipit `Repository`/`Stack` fixture (`branch: 'master'`).
2. Build payload: `{'ref' => 'refs/heads/master', 'after' => 'deadbeef', 'repository' => {'full_name' => 'victim-org/private-repo', 'owner' => {'login' => 'org-with-no-secret'}}}`.
3. `request.headers['X-Github-Event'] = 'push'`; omit `X-Hub-Signature` or set it to garbage (e.g., `'sha1=garbage'`).
4. `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeef']) { post :create, body: payload.to_json, as: :json }`.
5. Assert both sides of the binding explicitly before the fix: `assert_not_equal 'org-with-no-secret', victim_repository.owner` while the job is still enqueued for `victim_stack`, demonstrating verification organization != mutated repository owner.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```
