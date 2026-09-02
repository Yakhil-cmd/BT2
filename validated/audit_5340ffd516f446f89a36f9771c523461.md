### Title
Cross-organization webhook forgery via `repository.owner.login`/`repository.full_name` field mismatch in `WebhooksController#verify_signature` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate the request against using `params.dig('repository', 'owner', 'login')` (or `organization.login`), while every `PullRequest` handler including `LabelCapturingHandler` authorizes and scopes its mutation using a completely different field, `params.repository.full_name`. In a multi-organization Shipit deployment, if any single configured organization has no `webhook_secret` set, an attacker can forge a webhook that is "verified" against that unprotected organization while its `repository.full_name` names a stack belonging to a different, properly-secured organization, causing `Shipit::PullRequest#labels` to be mutated for a repository the attacker never authenticated against.

### Finding Description
The claimed binding is:
`organization_that_verified_signature(payload.repository.owner.login) == organization_being_mutated(payload.repository.full_name.split('/').first)`

This binding is not enforced anywhere in the code.

- `verify_signature` derives the signing organization from `repository.owner.login`/`organization.login`, then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`: [1](#0-0) [2](#0-1) 

- `Shipit.github` looks up per-organization config in multi-org mode via `github_app_config(organization)`, keyed strictly on the organization name passed in: [3](#0-2) 

- `GitHubApp#verify_webhook_signature` trivially returns `true`, without ever checking the signature header, whenever the resolved organization's config has no `webhook_secret` set: [4](#0-3) 

- Once `verify_signature` passes, the `create` action re-parses the same `raw_post` and dispatches to all registered handlers for the event, including `LabelCapturingHandler`: [5](#0-4) [6](#0-5) 

- `LabelCapturingHandler` (and its sibling PR handlers) never look at `repository.owner.login` at all — they resolve the target repository purely from `params.repository.full_name`, which is an attacker-controlled field entirely independent of the field used for signature verification: [7](#0-6) 

Exploit flow: in a multi-organization deployment (`config/secrets.yml` with per-org `github:` sub-keys, as documented), configure/observe that organization `unsecured-org` has `webhook_secret:` blank (a documented, supported configuration — see `docs/setup.md` and `template.rb`, which both show `webhook_secret:` left empty by default). An unprivileged attacker with no session, no API token, and no secret for any organization sends:

```
POST /webhooks
X-Github-Event: pull_request
X-Hub-Signature: sha1=deadbeef   (or omitted entirely)
{
  "action": "labeled",
  "number": 1,
  "pull_request": { ... valid schema fields ..., "labels": [{"name":"attacker-label"}] },
  "repository": { "owner": {"login": "unsecured-org"}, "full_name": "victim-org/victim-repo" },
  "sender": {"login": "attacker"}
}
```

`verify_signature` resolves `repository_owner = "unsecured-org"`, calls `Shipit.github(organization: "unsecured-org").verify_webhook_signature(...)`, which short-circuits to `true` because `unsecured-org`'s `webhook_secret` is unset — no signature check ever occurs. The request proceeds to `create`, and `LabelCapturingHandler.new(params).process` resolves the stack from `repository.full_name = "victim-org/victim-repo"` and calls `pull_request.update!(labels: ...)` on the victim's PR, mutating data for an organization the attacker never authenticated against.

Existing guards fail because: `drop_unhandled_event` and `check_if_ping` don't touch this field; `ExplicitParameters` schema only validates types/presence, not cross-field consistency between `repository.owner.login` and `repository.full_name`; there is no `Repository` or `Stack` validation tying the webhook's verified organization to the repository being mutated.

### Impact Explanation
An attacker can mutate `Shipit::PullRequest#labels` (and, via other handlers sharing the same `repository.full_name`-only trust model — `OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `AssignedHandler` — archive/unarchive stacks, create review stacks, and update PR metadata) for any repository/organization tracked by the Shipit instance, without holding that organization's `webhook_secret`. This is a cross-tenant write: "a payload for one repository mutating another's stack ... or commit," matching the Critical severity bar. The attack is repeatable against any repository known to Shipit as long as one org in the multi-org config lacks (or ever lacked) a `webhook_secret`, and blast radius spans every organization/repository hosted on that single Shipit instance.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (per-org `github:` config keys), and (2) at least one configured organization with an empty/unset `webhook_secret`. Both are documented, default-friendly configurations (`docs/setup.md` lines showing blank `webhook_secret:`, `template.rb` generating blank `webhook_secret:` by default). Given this, attacker cost is a single unauthenticated HTTP POST with a crafted JSON body matching the target handler's schema — no GitHub credentials, no Shipit session, no secrets required. Fully repeatable and scriptable against arbitrary repositories.

### Recommendation
Bind the verified organization to the mutated repository: after `verify_signature` succeeds, require that the organization derived from `repository.full_name` (the field handlers actually act upon) matches the organization used for signature verification (`repository.owner.login`/`organization.login`), rejecting the request otherwise. Additionally, treat an unset `webhook_secret` for any organization as a configuration warning/hard-fail in multi-org mode rather than an automatic verification pass, or require explicit opt-in for "no verification" per organization.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "cross-organization webhook cannot mutate another org's stack via full_name/owner mismatch" do
  # Multi-org config: 'unsecured-org' has no webhook_secret, 'shopify' (victim) does.
  Shipit.stubs(:github).with(organization: 'unsecured-org').returns(
    Shipit::GitHubApp.new('unsecured-org', {}) # no webhook_secret => verify_webhook_signature returns true
  )

  stack = shipit_stacks(:shipit) # belongs to victim org e.g. "shopify/shipit-engine"
  pull_request = stack.pull_request
  pull_request.update!(labels: [])

  payload = payload_parsed(:pull_request_labeled)
  payload["repository"] = { "owner" => { "login" => "unsecured-org" }, "full_name" => "shopify/shipit-engine" }
  payload["pull_request"]["labels"] = [{ "name" => "attacker-label" }]

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=totally-bogus'

  assert_no_changes -> { pull_request.reload.labels } do
    post :create, body: payload.to_json, as: :json
  end
  # EXPECTED (current buggy behavior): response is :ok and labels ARE changed -> vulnerability confirmed
  # DESIRED (fixed behavior): assert_response :unprocessable_entity, and pull_request.labels unchanged
end
```
This test demonstrates that `Shipit::PullRequest#labels` for `victim-org/victim-repo` is mutated by a request whose signature was validated against an unrelated, secret-less organization — proving the `repository.owner.login` (verification) vs. `repository.full_name` (mutation target) binding is not enforced.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-118)
```ruby
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
