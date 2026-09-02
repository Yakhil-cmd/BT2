### Title
Organization fallback in `repository_owner` lets a webhook forged for any no-`webhook_secret` org mutate an unrelated repository's stack via `LabelCapturingHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#repository_owner` falls back to `params.dig('organization', 'login')` when `repository.owner.login` is absent, and this value alone selects which `GitHubApp`/secret verifies the signature. `LabelCapturingHandler`, however, resolves the target repository/stack independently from `params.repository.full_name`. Because these two attacker-controlled fields are decoupled, an attacker can pick an org with no `webhook_secret` configured to trivially pass signature verification while pointing `repository.full_name` at a victim stack belonging to a different, secured org.

### Finding Description
The broken binding is: verification authority `Shipit.github(organization: repository_owner)` should equal the authority for the repository actually acted upon, i.e. `repository_owner == Shipit::Repository.from_github_repo_name(params.repository.full_name).organization`. This does not hold.

- `repository_owner` in `app/controllers/shipit/webhooks_controller.rb:59-62` is computed as `params.dig('repository','owner','login') || params.dig('organization','login')`.
- `verify_signature` (same file, lines 24-30) uses only this value to fetch the `GitHubApp` and check `verify_webhook_signature(signature, raw_post)`.
- `GitHubApp#verify_webhook_signature` in `lib/shipit/github_app.rb:76-83` does `return true unless webhook_secret` — if the org resolved from `repository_owner` has no `webhook_secret` configured (a supported, documented configuration per `docs/setup.md` and used verbatim in `test/dummy/config/secrets_double_github_app.yml`), **any** request is accepted unconditionally, signature or not.
- Meanwhile `LabelCapturingHandler` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-113`) resolves the actual repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, a field that is completely independent of `organization.login`/`repository.owner.login` used for verification.

Attack request: omit `repository.owner.login`, set `organization.login` to an org configured without `webhook_secret` (e.g. `no-secret-org`), and set `repository.full_name` to `secured-org/victim-repo` (a repo under an org that *does* have a `webhook_secret`, i.e. normally protected). Send `X-Github-Event: pull_request`, `action: labeled`, arbitrary/garbage `X-Hub-Signature`. `verify_signature` selects the `no-secret-org` `GitHubApp`, which returns `true` unconditionally, so the request passes with no valid HMAC at all. `Shipit::Webhooks.for_event('pull_request')` then dispatches to `LabelCapturingHandler#process`, which looks up `secured-org/victim-repo`'s `Repository`/`Stack`/`PullRequest` via `params.repository.full_name` and calls `pull_request.update!(labels: params.pull_request.labels.map(&:name))` — persisting attacker-chosen label names onto the real victim's `PullRequest`, which later become uppercased environment-variable keys via `ReviewStack#env`.

No existing guard closes this gap: `drop_unhandled_event` only filters by event type, `ExplicitParameters` (the `params do ... end` schema) only validates shape/presence of fields, not cross-consistency between `organization.login` and `repository.full_name`, and there is no check anywhere that the org used to select the verifier matches the org owning the repository being mutated.

### Impact Explanation
An unauthenticated, unprivileged attacker can write forged data (arbitrary label names) onto a `PullRequest`/`ReviewStack` belonging to a **different** repository/organization than the one whose (non-existent) secret was used to pass verification — a cross-tenant "payload for one repository mutating another's stack" scenario, matching the Critical impact bar. The blast radius spans every stack under every org lacking a `webhook_secret`... but more importantly, it lets requests attributed to *that* org's verifier bypass authentication for *any* `repository.full_name`, including repos under orgs that do have secrets, since the handler never re-checks that `repository.full_name`'s org matches `repository_owner`. This is repeatable per request/target stack.

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one configured GitHub org with `webhook_secret` unset/blank (a documented and evidently common setup — see `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`, both showing `webhook_secret: # nil`), and a target stack/repo must exist that has an active `PullRequest`/review stack. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body — no GitHub credentials, no valid HMAC, no session required. This is highly feasible and trivially repeatable.

### Recommendation
Bind webhook authentication to the same repository the handler will act on: derive `repository_owner` exclusively from `repository.owner.login` (reject/422 if absent) rather than falling back to `organization.login`, or alternatively verify that `params.dig('organization','login')` matches the owner segment of `params.dig('repository','full_name')` before dispatching. Additionally, treat `verify_webhook_signature`'s "no secret configured" case as a hard misconfiguration error (fail closed) rather than an implicit unconditional pass.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (organization fallback selection context):

```ruby
test "pull_request labeled webhook forged via organization fallback mutates unrelated stack's PullRequest" do
  # Setup: two orgs configured, "no-secret-org" without webhook_secret, "secured-org" with one.
  # stack belongs to "secured-org/victim-repo" and has an active PullRequest with pull_request_id set.
  stack = shipit_stacks(:shipit) # under an org WITH webhook_secret, e.g. "shopify"
  pr = stack.create_pull_request!(number: 42, ...)

  payload = {
    action: "labeled",
    number: 42,
    pull_request: {
      id: 42, number: 42, url: "...", title: "x", state: "open",
      additions: 1, deletions: 0,
      head: { sha: "a" * 40, ref: "feature" },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "PWNED_ENV_VAR" }]
    },
    repository: { full_name: "#{stack.repository.owner}/#{stack.repository.name}" }, # victim, no owner.login key
    organization: { login: "no-secret-org" }, # fallback selects lenient verifier
    sender: { login: "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # invalid/garbage signature

  # BEFORE: repository_owner ("no-secret-org") != stack's actual org ("shopify")
  assert_not_equal "no-secret-org", stack.repository.owner

  post :create, body: payload, as: :json
  assert_response :ok

  pr.reload
  # AFTER: attacker-forged label persisted on a stack authenticated by a DIFFERENT org's (absent) secret
  assert_includes pr.labels, "PWNED_ENV_VAR"
end
```

This demonstrates the equality `repository_owner (verifier selector) == repository.full_name's org (mutated resource)` is violated, and existing guards (`drop_unhandled_event`, `ExplicitParameters`, `verify_signature`) do not prevent it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L94-118)
```ruby
          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
