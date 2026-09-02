### Title
Attacker-chosen `repository.owner.login` selects the GitHub App/webhook_secret used for verification, letting a payload targeting one repository be authenticated against a different (or unconfigured) organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` derives which `GitHubApp`/`webhook_secret` to verify a webhook against from `params.dig('repository','owner','login')` — a value the attacker fully controls in the raw JSON body — while the handlers that actually mutate state (e.g. `Handlers::PullRequest::OpenedHandler`) resolve the target `Shipit::Repository`/stack from a *separate* field, `params.repository.full_name`. An attacker can therefore craft a payload whose `repository.owner.login` names an organization/app config with no `webhook_secret` (making `GitHubApp#verify_webhook_signature` return `true` unconditionally, per `return true unless webhook_secret`) while `repository.full_name` in the same payload points at a victim repository governed by a different, secret-protected GitHub App/org.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:
`repository_owner_used_for_signature_verification == repository_owner_that_actually_owns_the_mutated_record`

In `app/controllers/shipit/webhooks_controller.rb`:
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
```
`repository_owner` is read straight from the attacker-supplied JSON body, and used only to pick *which* `GitHubApp` config's secret to check the signature against (`lib/shipit/github_app.rb`):
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
```
If no `webhook_secret` is configured for the org named in `repository.owner.login`, verification short-circuits to `true` regardless of the (possibly malformed) signature header — the `signature.split('=',2)` / nil-`signature` detail from the prompt is a secondary contributor but not required, since `webhook_secret` being absent already bypasses the comparison entirely.

Once `verify_signature` passes, `WebhooksController#create` dispatches the full, unvalidated `params` to every registered handler for the event:
```ruby
Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
```
For `pull_request`/`opened`, `Handlers::PullRequest::OpenedHandler#repository` resolves the actual target using a *different* JSON field:
```ruby
def repository
  @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
end
```
Nothing ties `repository.full_name` back to the `repository.owner.login` that was used to select the verifying secret. An attacker submits one JSON body where `repository.owner.login` = an org with no secret configured (or any org they can otherwise pass verification for) and `repository.full_name` = `"victim-org/victim-repo"`. The handler then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` against the victim repository's real review-stack scope — a payload nominally "verified" for one identity mutates another party's records.

Existing guards do not prevent this: `drop_unhandled_event` only checks whether handlers exist for the event name; `verify_signature` only checks the HMAC over the raw body against a secret chosen by attacker-controlled data, it never cross-checks that the verified organization matches the repository actually being acted upon; the `ExplicitParameters` schema in `OpenedHandler` only validates types/presence, not cross-field/tenant consistency.

### Impact Explanation
An unauthenticated internet requester can drive `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler` (and the other PR handlers fanned out via `Shipit::Webhooks.for_event('pull_request')`) to create/mutate review-stack records for an arbitrary victim repository configured in Shipit, provided any organization exists (or can be referenced) whose `GitHubApp` has no `webhook_secret` configured. This is a cross-tenant state-manipulation / authentication-bypass primitive: state belonging to repository B is written using a payload that was only ever authenticated (trivially, due to `return true unless webhook_secret`) for identity A. Repeatable for every repository under Shipit's management as long as at least one no-secret org config is reachable via `Shipit.github(organization: ...)`.

### Likelihood Explanation
Requires that at least one configured GitHub App/org in the running Shipit instance lacks a `webhook_secret` (a legitimate, documented configuration state, not an exotic one — `webhook_secret` is `.presence`-checked and optional in `GitHubApp#initialize`). No GitHub credentials, session, or team membership is needed; the attacker only needs to know or guess the name of such an org and the `full_name` of the victim repository, both of which are typically public information (Shipit's own configured orgs/repos). Attack cost is a single unauthenticated HTTP POST to `/webhooks`.

### Recommendation
Bind signature verification to the same repository/organization identity that the handler will act on: after resolving the target `Shipit::Repository` from `repository.full_name`, verify that its configured organization/owner matches `repository_owner`, and require a `webhook_secret` to be present (reject rather than accept-by-default when `webhook_secret` is unset) for every organization that owns registered repositories. Additionally, in `GitHubApp#verify_webhook_signature`, treat a missing/malformed `X-Hub-Signature` (`algorithm`/`signature` nil) as an explicit verification failure rather than passing it to `SecureCompare.secure_compare`, independent of whether `webhook_secret` is configured.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub, mirroring existing tests in that file):
```ruby
test "pull_request opened for org with no webhook_secret mutates a different org's repository review stack" do
  # Arrange: victim repository/stack belongs to an org with webhook_secret configured
  victim_repo = shipit_repositories(:shipit) # e.g. full_name "shopify/shipit-engine"
  attacker_org_login = 'no-secret-org' # GithubApp config for this org has webhook_secret == nil

  # Confirm binding under test, BEFORE tracing:
  # assert_equal victim_repo.owner_login, repository_owner_used_for_verification  <-- this is the equality that should hold and does not

  Shipit.stubs(:github).with(organization: attacker_org_login)
        .returns(Shipit::GitHubApp.new(attacker_org_login, {})) # no webhook_secret -> verify_webhook_signature returns true always

  payload = {
    action: 'opened',
    number: 99,
    pull_request: {
      id: 1, number: 99, url: 'https://api.github.com/x', title: 't', state: 'open',
      additions: 1, deletions: 0,
      head: { sha: 'abc123', ref: 'feature' },
      user: { login: 'attacker' }, assignees: [], labels: []
    },
    repository: { full_name: victim_repo.full_name, owner: { login: attacker_org_login } },
    sender: { login: 'attacker' }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'garbagewithnoequalssign'

  assert_difference -> { victim_repo.review_stacks.count }, 1 do
    post :create, body: payload, as: :json
  end
  assert_response :ok
  # Assert both sides of the equality after the request: verification succeeded for attacker_org_login
  # but the mutated record belongs to victim_repo, which is NOT owned by attacker_org_login.
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-55)
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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```

**File:** test/controllers/webhooks_controller_test.rb (L94-107)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
    end
```
