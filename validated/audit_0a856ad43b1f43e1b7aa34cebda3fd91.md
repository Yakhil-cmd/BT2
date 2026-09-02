### Title
Signature verification is scoped to `repository.owner.login`, not `repository.full_name`, allowing a low-privileged multi-org attacker to forge webhooks that mutate a victim org's `Stack`/`ReviewStack` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify against using `repository_owner`, which is read from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). All downstream `pull_request.*` handlers (e.g. `OpenedHandler`, `ReopenedHandler`, `LabeledHandler`) instead resolve the target `Shipit::Repository` using `params.repository.full_name` via `Shipit::Repository.from_github_repo_name`. These two payload fields are never checked for consistency, so in a multi-org deployment an attacker who controls (or names) an org with no configured `webhook_secret` can pass signature verification trivially while pointing `full_name` at a different, victim org's tracked repository, causing a real `ReviewStack`/`Stack` to be created or mutated for the victim.

### Finding Description
The claimed binding is: `repository_owner` (the org whose `webhook_secret` was used to authenticate the request) == `owner` of the `Shipit::Repository` row loaded by `from_github_repo_name(params.repository.full_name)`.

Tracing the code:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and uses it to pick the GitHub App config: `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that specific org's `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) .
- In multi-org mode, `Shipit.github(organization:)` looks up a **per-organization** config keyed by the `organization` argument and raises `GithubOrganizationUnknown` only if that org name is not configured at all: `config = github_app_config(organization); raise GithubOrganizationUnknown, organization if config.nil?` [4](#0-3) . So as long as the attacker names an org that IS configured (even a legitimately-installed org with a blank `webhook_secret`, as shown in the multi-org fixture `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`), the check passes.
- After signature verification, `OpenedHandler#repository` (and siblings) independently look up the target repository via a **different field**: `Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new` [5](#0-4) , and `Repository.from_github_repo_name` simply splits `full_name` on `/` and does a `find_by(owner:, name:)` [6](#0-5) .

Because the JSON body is fully attacker-controlled (unauthenticated `POST /webhooks`, no session, no API token, no secrets required), `repository.owner.login`/`organization.login` and `repository.full_name` can be set to unrelated values. Exploit request:
```
X-Github-Event: pull_request
X-Hub-Signature: sha1=anything   (irrelevant, see below)
{
  "action": "opened",
  "number": 2,
  "pull_request": {... "head": {"ref": "evil-branch"}, "labels": [], ...},
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": {"login": "attacker-org"}
  },
  "sender": {"login": "attacker-login"}
}
```
- `repository_owner` resolves to `"attacker-org"`. If `attacker-org` is a configured org (e.g. it is a real, separate GitHub App install in this Shipit instance) whose `webhook_secret` is unset, `verify_webhook_signature` returns `true` for **any** signature value, so the request passes signature verification entirely under `attacker-org`'s (secret-less) identity.
- `OpenedHandler#repository` then resolves `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")`, which is a real tracked `Repository` row belonging to the victim org (not `attacker-org`), and `provision?`/`review_stacks_enabled` are evaluated against that **victim** repository's real configuration, not a `NullRepository`.
- If the victim repository has `review_stacks_enabled` and an applicable `provisioning_behavior`, `ReviewStackAdapter#find_or_create!` creates a real `ReviewStack`/`Stack` and `PullRequest` scoped to the victim `Repository`, with attacker-chosen `branch` (`pull_request.head.ref`), `environment` (`"pr#{number}"`), and PR metadata [7](#0-6) .

None of the existing guards prevent this: `drop_unhandled_event` only checks the event type is registered; `verify_signature` authenticates against the org named in the payload itself (attacker-chosen), not against the org that actually owns the target `Repository` row; the `ExplicitParameters` schemas on the handlers only require `repository.full_name` to be a `String`, never that it is consistent with `repository.owner.login`; and `Repository.from_github_repo_name`/model validations only validate format of the owner/name strings, not cross-org authorization.

### Impact Explanation
An attacker who controls (or can merely name) one configured-but-secretless GitHub org in a multi-org Shipit deployment can forge `pull_request` (and similarly `push`/`status`/other) webhooks that are authenticated as that org but act on **any other tracked repository's** `Shipit::Repository`/`Stack`/`ReviewStack`/`PullRequest` rows by simply setting `repository.full_name` to the victim's `owner/name`. This is a payload for one repository mutating another repository's stack/PR data — matching the **Critical** impact category ("a payload for one repository mutating another's stack, commit, task or team"). The attack is fully repeatable against any tracked repository as long as the attacker's named org has no `webhook_secret`, and is not limited to `pull_request.opened` — every handler that derives its target `Repository` from `params.repository.full_name` (`OpenedHandler`, `ReopenedHandler`, `LabeledHandler`/`UnlabeledHandler`, `AssignedHandler`, etc.) is affected the same way.

### Likelihood Explanation
This requires the specific but realistic multi-org configuration documented in `docs/setup.md` ("Using Multiple Github Applications") where `secrets.github` has multiple top-level org keys, and at least one configured org has a blank/unset `webhook_secret` (shown as the norm in the shipped example configs `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`, both with `webhook_secret: # nil`). Given that, the attacker's cost is a single unauthenticated HTTP POST with a crafted JSON body — no GitHub signature, session, or token is needed. In single-org mode the vulnerability does not manifest, because `Shipit.github(organization:)` ignores the `organization` argument entirely and always uses the one global config/secret, so the split between `repository_owner` and `full_name` doesn't let the attacker choose a different secret.

### Recommendation
In `WebhooksController#verify_signature`, derive `repository_owner` used for GitHub App/secret selection from the **same** value later used to resolve the `Repository` (i.e., parse it consistently from `repository.full_name`, not from `repository.owner.login`/`organization.login`), or explicitly validate that `repository.owner.login` matches the owner segment of `repository.full_name` before trusting either. Additionally, handlers should not silently treat a secretless org as authorization to mutate arbitrarily-named repositories — the `Repository` row resolved by `from_github_repo_name` should be cross-checked against the authenticated `repository_owner`, rejecting the webhook if they diverge.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_cross_org_test.rb
require "test_helper"

module Shipit
  class WebhooksCrossOrgTest < ActionController::TestCase
    tests Shipit::WebhooksController

    test "signature scoped to attacker-org must not authorize mutation of victim-org's tracked repository" do
      # Binding under test:
      #   repository_owner authenticated == owner of Repository row loaded by from_github_repo_name
      # i.e. assert_equal "victim-org", repository_owner  <-- should hold if binding is enforced

      victim_repo = shipit_repositories(:shipit) # owner: "shopify" (victim org), tracked, review_stacks_enabled
      victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_all)

      # attacker-org is configured in secrets.github but has no webhook_secret
      Shipit.expects(:github).with(organization: "attacker-org")
            .returns(stub(verify_webhook_signature: true))

      payload = payload_parsed(:pull_request_opened) # existing PR-opened fixture
      payload["repository"]["full_name"] = "#{victim_repo.owner}/#{victim_repo.name}"
      payload["repository"]["owner"] = { "login" => "attacker-org" }

      @request.headers["X-Github-Event"] = "pull_request"
      @request.headers["X-Hub-Signature"] = "sha1=doesnotmatter"

      assert_difference -> { Shipit::ReviewStack.count }, 1 do
        post :create, body: payload.to_json, as: :json
      end

      created = Shipit::ReviewStack.last
      # Binding equality that SHOULD hold but does not:
      assert_equal "attacker-org", created.repository.owner,
        "created ReviewStack.repository belongs to victim org 'shopify', not authenticated 'attacker-org' - binding is broken"
    end
  end
end
```
This test demonstrates that `repository_owner` (authenticated as `"attacker-org"`, whose secret check trivially passed) diverges from `created.repository.owner` (which is `"shopify"`, the victim), proving the binding claimed in the question is broken and a `ReviewStack` was created for a repository not authenticated by the request.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def environment
            "pr#{params.number}"
          end
```
