### Title
`repository.owner.login` used to select signing org while `repository.full_name` selects the mutated stack lets an attacker forge a `pull_request`/`unlabeled` event that archives or unarchives another org's review stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the HMAC secret) using `repository.owner.login` [1](#0-0) , while every `pull_request` handler (e.g. `UnlabeledHandler`) resolves the repository/stack to mutate using `repository.full_name` from the same attacker-controlled JSON body [2](#0-1) . Nothing enforces that `full_name` belongs to `owner.login`, and `GitHubApp#verify_webhook_signature` trivially returns `true` when the org resolved for signing has no `webhook_secret` configured [3](#0-2) .

### Finding Description
The broken binding, stated as an equality that the code assumes but never checks:

`Organization(repository.owner.login) == Organization(repository.full_name.split('/').first)`

Trace:
1. `verify_signature` computes `repository_owner = params.dig('repository','owner','login')` and fetches `Shipit.github(organization: repository_owner)`, then calls `github_app.verify_webhook_signature(signature, raw_post)` [4](#0-3) .
2. `verify_webhook_signature` short-circuits: `return true unless webhook_secret` — i.e., if the org picked via `owner.login` has no `webhook_secret` configured, **any** payload, with **any** or no signature header, is accepted [3](#0-2) .
3. `create` then dispatches to `Shipit::Webhooks.for_event('pull_request')`, which for `action=unlabeled` invokes `UnlabeledHandler.call(params)` [5](#0-4) .
4. `UnlabeledHandler#repository` looks up the target repository using `params.repository.full_name` — a completely independent field from the one used for signature verification [2](#0-1) .
5. `handle` then calls `stack.archive!` or `stack.unarchive!` on the resolved victim stack, based purely on label-membership logic — no CI/authorization checks in this path [6](#0-5) .

Exploit request: attacker crafts a raw JSON body with `X-Github-Event: pull_request`, `repository.owner.login` set to an org string that has no `webhook_secret` configured in Shipit's app config (e.g., an org never onboarded, or one deliberately left unconfigured), and `repository.full_name` set to `"victim-org/victim-repo"` (an org that *is* provisioned in Shipit and does have a real secret). `action` is `"unlabeled"`, `pull_request.state` is `"open"`, and `pull_request.labels` is crafted to trigger `archive?`/`unarchive?` for the victim repository's actual provisioning behavior/label. No `X-Hub-Signature` header, or an arbitrary one, is required because step 2 bypasses verification entirely for the no-secret org.

Why existing guards fail: `drop_unhandled_event` only checks the event name exists in `Shipit::Webhooks.handlers`, not the payload's internal consistency [7](#0-6) . `GithubOrganizationUnknown` only fires when `repository_owner` maps to *no* configured org at all — it does not fire, and does not help, when the attacker-chosen owner *is* configured but simply has no secret [8](#0-7) , confirmed by the existing test `"unknown github organization logs and returns unprocessable entity"` which only covers the fully-unknown-org case, not the no-secret-org case [9](#0-8) . The `ExplicitParameters` schema for `UnlabeledHandler` only requires `repository.full_name` to be a `String`; it does not require or check that it corresponds to `repository.owner.login` [10](#0-9) . The "ignore_ci true" condition on the target stack is irrelevant to this specific handler path — `Commit#deployable?`'s CI short-circuit [11](#0-10)  matters for deploy triggering elsewhere, not for `archive!`/`unarchive!`, which have no CI gating at all; it only amplifies a *different, related* class of impact (a forged commit becoming instantly "shippable" once other webhook paths, e.g. `status`/`push`, are similarly forged) but does not change whether this specific archive/unarchive bug exists.

### Impact Explanation
An attacker can force-archive or force-unarchive review stacks belonging to a repository/org they do not control and did not authenticate as, by simply choosing a "no-secret" (unconfigured or misconfigured) org name for `repository.owner.login` while pointing `repository.full_name` at any org whose repository is tracked by the target Shipit instance. This is a cross-tenant/cross-repository mutation: a payload naming org A's owner authenticates against org A's (missing) secret while mutating org B's stack state. This matches "a payload for one repository mutating another's stack" (Critical). The blast radius covers any Shipit deployment with at least one org/app entry lacking a `webhook_secret` (a plausible legitimate configuration state, e.g., staging integrations, orgs onboarded before secrets were rotated in, or public no-secret installations) — repeatable against every review-stack-enabled repository on the instance, once per PR/label state transition.

### Likelihood Explanation
The attack requires: (a) the Shipit instance to have at least one configured GitHub org/app without a `webhook_secret` (`@webhook_secret = @config[:webhook_secret].presence`) [12](#0-11) , and (b) a victim repository with `review_stacks_enabled` and a provisioning-label policy that the attacker can flip via `unlabeled`. The attacker needs no GitHub credentials for the victim org, no Shipit session, and no valid HMAC signature — only knowledge of an unconfigured org name (which may be guessable, e.g. their own personal GitHub org) and the victim's `owner/repo` full name (public information). Cost is a single unauthenticated HTTP POST to `/webhooks`; fully repeatable and scriptable.

### Recommendation
In `WebhooksController#verify_signature` (or in the base `Shipit::Webhooks::Handlers::Handler`), require and enforce that `repository.full_name.split('/').first == repository.owner.login` (and reject/`head 422` if this invariant fails) before dispatching to any handler. Additionally, treat a missing `webhook_secret` as a hard misconfiguration to reject (or require explicit opt-in), rather than having `verify_webhook_signature` silently `return true` when no secret is configured — an org with no secret should not be able to authenticate arbitrary payloads for the rest of the system.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
```ruby
test "pull_request/unlabeled cannot archive a victim stack when owner.login and full_name diverge" do
  # Setup: configure Shipit.github_apps with an org "attacker-org" that has NO webhook_secret,
  # and ensure "shopify" (owning shipit_stacks(:shipit)'s repository) HAS a real webhook_secret.
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(ignore_ci: true)
  victim_repo = victim_stack.repository
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: 'prevent-with-label')

  binding_before = victim_stack.reload.archived?

  request.headers['X-Github-Event'] = 'pull_request'
  # no X-Hub-Signature header sent at all
  body = {
    action: 'unlabeled',
    number: 1,
    pull_request: {
      id: 1, number: 1, url: 'https://x', title: 't', state: 'open',
      additions: 0, deletions: 0,
      head: { sha: 'abc', ref: 'branch' },
      user: { login: 'attacker' },
      assignees: [],
      labels: [{ name: victim_repo.provisioning_label_name }]
    },
    repository: { owner: { login: 'attacker-org' }, full_name: victim_repo.github_repo_name },
    sender: { login: 'attacker' }
  }.to_json

  post :create, body: body, as: :json

  binding_after = victim_stack.reload.archived?

  # Assert the invariant: since "attacker-org" did not authenticate this payload for
  # victim_repo's org, the archived state must be unchanged.
  assert_equal binding_before, binding_after,
    "Unauthenticated payload from attacker-org mutated victim_repo's stack archive state"
end
```
This test should fail on current code (the stack becomes archived) unless `Shipit.github_apps["attacker-org"]` genuinely has no secret configured in the test fixture — which is the precise precondition this finding depends on, and must be set up explicitly in the fixture/config used for the test to demonstrate the bypass.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** test/controllers/webhooks_controller_test.rb (L109-127)
```ruby
    test "unknown github organization logs and returns unprocessable entity" do
      @request.headers['X-Github-Event'] = 'push'

      payload = JSON.parse(payload(:push_master))
      payload["repository"]["owner"]["login"] = "unknown-org"

      Shipit.stubs(:github).raises(Shipit::GithubOrganizationUnknown.new("unknown-org"))
      Rails.logger.expects(:warn).with([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=push",
        "repository_owner=unknown-org",
        "unknown_organization=unknown-org",
        "status=422"
      ].join(' '))

      post :create, body: payload.to_json, as: :json
      assert_response :unprocessable_entity
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
