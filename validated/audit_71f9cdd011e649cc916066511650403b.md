### Title
Webhook signature verification is a no-op for orgs without a configured `webhook_secret`, allowing unauthenticated forged `pull_request` events - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the org has no `webhook_secret` configured, before any signature or algorithm check is performed. This means `Shipit::WebhooksController#verify_signature` accepts *any* forged payload for that org, letting an attacker drive `pull_request` action=`labeled` events straight to `LabelCapturingHandler`, which persists attacker-chosen label names onto the target `ReviewStack`'s `PullRequest`, which `ReviewStack#env` later turns into uppercased environment variables.

### Finding Description
The claimed invariant is: `verified == (HMAC(webhook_secret, raw_body) == supplied_signature)` for every accepted webhook. In reality, for an org configured without a `webhook_secret`:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret   # <-- short-circuits before any comparison
  ...
end
``` [1](#0-0) 

`webhook_secret` is `@config[:webhook_secret].presence`, set at initialization from org config [2](#0-1) . `WebhooksController#verify_signature` resolves the `GitHubApp` for the request's `repository_owner` and calls this method with whatever header/body the attacker sent [3](#0-2) . When the org has no secret, `verified` is `true` regardless of the header contents (sha1, sha256, garbage, or absent header entirely) — the "legacy sha1" detail in the prompt is actually irrelevant here since the algorithm branch (`return false unless algorithm == 'sha1'`) is never reached for a no-secret org.

Once accepted, `Shipit::Webhooks.for_event('pull_request')` dispatches to `LabelCapturingHandler` [4](#0-3) . For `action=labeled` on an existing, non-archived stack, `capture_labels` runs:
```ruby
pull_request.update!(labels: params.pull_request.labels.map(&:name))
``` [5](#0-4) 
`repository` is resolved purely from `params.repository.full_name`, with no cross-check against the org that authenticated the request [6](#0-5) . The target `ReviewStack` is looked up by `environment: "pr#{params.number}"` [7](#0-6) [8](#0-7) .

Persisted labels then feed `ReviewStack#env`:
```ruby
def env
  return super unless pull_request.present?
  super.merge(
    pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
  )
end
``` [9](#0-8) 
This merged env hash is used by `Commands`/`Command` when spawning git and deploy/rollback processes for the stack [10](#0-9) , so an attacker can inject arbitrary uppercase environment flags (e.g. names matching feature flags any deploy/rollback script checks) into the process environment of that review stack's tasks.

No other guard intervenes: `drop_unhandled_event` only checks that a handler exists for the event type, not authenticity [11](#0-10) ; there is no per-repository secret, only per-org; and `ExplicitParameters` only validates payload shape, not origin.

### Impact Explanation
Any org whose GitHub App/webhook config omits `webhook_secret` has webhook authentication fully disabled — not merely weakened by an algorithm-confusion trick. An attacker who knows (or guesses) the repository owner login and an existing PR number/environment (`pr<N>`) for a review stack under that org can forge arbitrary `pull_request` webhooks, causing `LabelCapturingHandler` to overwrite that stack's `PullRequest#labels`, which are subsequently injected as environment variables into every command run against that review stack (deploys, rollbacks, git operations). This is a write to another party's record (the `PullRequest`/`ReviewStack`) without any authentication of the request's origin, and it can influence the environment passed into `Command`/spawned processes for that stack — matching "a payload for one repository mutating another's stack" / authentication bypass for forged webhooks. It is repeatable against every repository/review stack that belongs to an org without a configured `webhook_secret`, but does **not** extend to orgs that do configure a secret (those are protected by the HMAC comparison).

### Likelihood Explanation
Preconditions: the specific org's `Shipit.github(organization:)` config must have no `webhook_secret` set (an operator/config choice, not attacker-controlled), and a review stack for a known PR number must already exist. Given that precondition, the attack is trivial and free: no valid signature, secret, or GitHub credentials are needed at all — a single unauthenticated `POST /webhooks` with `X-Github-Event: pull_request` and a JSON body claiming `action: "labeled"` for the target `repository.full_name`/`number` suffices. This is fully repeatable and requires no privileged GitHub role.

### Recommendation
Fail closed instead of open when no `webhook_secret` is configured: `verify_webhook_signature` should reject (`return false`) rather than `return true` when `webhook_secret` is blank, or Shipit should refuse to boot/register an org's GitHub App config without a `webhook_secret`. Additionally, support and require the modern `X-Hub-Signature-256` (SHA-256) header rather than only accepting `sha1`, and reject requests lacking a recognized signature algorithm.

### Proof of Concept
Under `test/controllers/shipit/webhooks_controller_test.rb` (or a new test file), for an org configured with no `webhook_secret`:
```ruby
test "pull_request labeled event is accepted and mutates PullRequest without any valid secret when org has no webhook_secret" do
  # Arrange: stub Shipit.github(organization: 'no-secret-org') to a GitHubApp built with config: { } (no webhook_secret)
  stack = shipit_review_stacks(:some_review_stack) # belongs to repository owned by "no-secret-org", environment "pr42"
  original_labels = stack.pull_request.labels

  payload = {
    action: "labeled",
    number: 42,
    pull_request: { ..., labels: [{ name: "FORGED_FLAG" }] },
    repository: { full_name: stack.repository.full_name, owner: { login: "no-secret-org" } },
    sender: { login: "attacker" }
  }.to_json

  # Act: no X-Hub-Signature header, or an arbitrary/incorrect one
  post shipit.hooks_path, params: payload,
       headers: { "X-Github-Event" => "pull_request", "Content-Type" => "application/json" }

  # Assert both sides of the binding:
  assert_response :ok                       # accepted despite forged/absent signature
  stack.pull_request.reload
  assert_equal ["FORGED_FLAG"], stack.pull_request.labels   # attacker-controlled write succeeded
  assert_equal "true", stack.env["FORGED_FLAG"]             # propagates into ReviewStack#env
end
```
This demonstrates `verified == true` even though no correct `HMAC(webhook_secret, body)` exists (because `webhook_secret` is absent), violating the intended equality and producing an unauthenticated write and environment-variable injection for the targeted stack.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-12)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L96-98)
```ruby
          def environment
            "pr#{params.number}"
          end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** lib/shipit/commands.rb (L24-50)
```ruby
    def env
      base_env
    end

    def git(*args)
      kwargs = args.extract_options!
      kwargs[:env] ||= base_env
      Command.new("git", *args, **kwargs)
    end
    ruby2_keywords :git if respond_to?(:ruby2_keywords, true)

    private

    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
    end
```
