### Title
`WebhooksController#verify_signature` authenticates against `params.repository.owner.login` while `Handler`/`EditedHandler` process against the independent, uncross-checked `params.repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify the HMAC using `repository_owner`, which is read from `params.dig('repository','owner','login')`, while every `Handler` subclass (including `EditedHandler`) looks up the target `Repository`/`Stack`/`PullRequest` using the completely independent field `params.repository.full_name`. There is no code anywhere that asserts these two attacker-supplied JSON fields agree, so a request that passes signature verification for one org can still be dispatched to mutate records belonging to a different org named in `full_name`.

### Finding Description
The claimed binding is: `app/org whose webhook_secret verified the request` == `org owning params.repository.full_name`.

Tracing the code:
- `WebhooksController#verify_signature` picks the verifying app via `Shipit.github(organization: repository_owner)`, where `repository_owner` comes from `params.dig('repository', 'owner', 'login')` (or `organization.login`) — [1](#0-0)  and [2](#0-1) .
- `Shipit.github` resolves the app config by that `organization` key only when running in multi-app mode; `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that org's `webhook_secret` is blank — [3](#0-2)  and [4](#0-3) .
- After `verify_signature` passes, `WebhooksController#create` dispatches the *entire raw JSON* to the handler, with no re-check: [5](#0-4) .
- `Handler#repository_name`/`#stacks` and every `PullRequest` handler (e.g. `EditedHandler#pull_request`) resolve the target repository from `params.repository.full_name` — a completely separate field from `repository.owner.login` used above: [6](#0-5)  and [7](#0-6) .

Nothing in `Handler`, `EditedHandler`, or `WebhooksController` cross-validates that `full_name`'s owner segment equals `repository.owner.login` (the value actually used to select the verifying app/secret). In a multi-app deployment (`docs/setup.md` "Using Multiple Github Applications", exercised by `test/dummy/config/secrets_double_github_app.yml`), an attacker can craft a body where `repository.owner.login` names an org whose `webhook_secret` is unset (an explicitly supported/optional configuration, shown as `webhook_secret: # nil` throughout the shipped example configs), which makes `verify_webhook_signature` return `true` with no signature at all, while `repository.full_name` names an entirely different, fully-secured org's tracked repository. The request sails through `verify_signature` and is handed to `EditedHandler#process`, which updates that other org's `PullRequest` record.

### Impact Explanation
An attacker with no session, no API token, and no secrets can cause a write (`PullRequest#update` with attacker-controlled `github_pull_request` JSON, and analogous writes in `LabeledHandler`, `AssignedHandler`, etc.) against a `Stack`/`PullRequest` belonging to an organization/repository the request never authenticated for. This is repeatable against any repository tracked by Shipit, for every PR-related handler, as long as one configured org in a multi-app deployment has no `webhook_secret` set. This matches the "payload for one repository mutating another's stack/commit/task" Critical category.

### Likelihood Explanation
Exploitability is conditioned on a specific, but explicitly documented and commonly-seen, configuration state: multi-app mode (`github:` keyed by organization) with at least one configured org having a blank/unset `webhook_secret` — a state the shipped example configs (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) present as valid ("webhook_secret: # nil"). Given that state, the attacker cost is a single unauthenticated POST to `/webhooks` with a crafted JSON body and no signature-cracking required. In single-app (default) mode this specific divergence is not exploitable since `organization:` is ignored entirely and only one shared secret exists.

### Recommendation
In `Handler`/`WebhooksController`, bind the verified organization to the object being mutated: pass the verified `repository_owner`/app identity into each `Handler.call`, and require that `params.repository.full_name.split('/').first` (or `params.repository.owner.login`) matches the organization whose secret actually verified the signature before any `Repository.from_github_repo_name`/`PullRequest` lookup proceeds. Additionally, do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in multi-app mode; require every configured org to set a secret.

### Proof of Concept
minitest plan in `test/controllers/webhooks_controller_test.rb` style (illustrative; actual file is out of scope per rules but describes the assertions needed):
1. Configure `Shipit.stubs(:secrets).returns(...)` with two orgs: `SecureOrg` (webhook_secret set) owning a tracked `Stack`/`PullRequest`, and `OpenOrg` (webhook_secret nil, no tracked repos).
2. Build a `pull_request.edited` JSON body with `repository.owner.login = "OpenOrg"` and `repository.full_name = "SecureOrg/target-repo"`, `number` matching an existing `PullRequest` under `SecureOrg`.
3. POST to `/webhooks` with `X-Github-Event: pull_request` and no valid `X-Hub-Signature` (or an arbitrary one).
4. Assert response is `:ok` (i.e., `verify_signature` passed via `OpenOrg`'s nil secret) — left side of binding: verifying org = `OpenOrg`.
5. Assert `SecureOrg`'s `PullRequest#github_pull_request` was updated — right side of binding: mutated repo owner = `SecureOrg`.
6. Assert these two differ, proving the binding "verifying org == owning org of full_name" is broken, and `EditedHandler#process` did NOT refuse to run.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-60)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
```
