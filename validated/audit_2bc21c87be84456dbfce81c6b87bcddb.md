### Title
Webhook signature verified against `repository.owner.login`'s org config while stack provisioning trusts `repository.full_name` for a different org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and its `webhook_secret`) to validate a webhook using `params.dig('repository','owner','login')`, but `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#repository` looks up the `Shipit::Repository` to provision using `params.repository.full_name`. Because the whole JSON body is attacker-supplied raw HTTP input rather than a value GitHub guarantees to be internally consistent, an attacker can set these two fields to different organizations, causing the signature check to run against an org with no (or a known/misconfigured) `webhook_secret` while the actual write (`ReviewStack` creation) is performed against a victim repository named in `full_name`.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:
`organization_verified_by_signature (params.repository.owner.login) == organization_that_owns(params.repository.full_name)`.

Trace:
- `Shipit::WebhooksController#verify_signature` computes `repository_owner` purely from the request body: `params.dig('repository', 'owner', 'login')` [1](#0-0)  and uses it to select the `GitHubApp` config: `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)` [2](#0-1) .
- `Shipit.github(organization:)` in multi-org mode (`github_default_organization` non-nil, i.e. per-org sub-config in `secrets.github`) resolves the config solely from the attacker-controlled `organization` argument via `github_app_config(organization)` [3](#0-2) .
- `GitHubApp#verify_webhook_signature` trivially returns `true` when that org's `webhook_secret` is blank: `return true unless webhook_secret` [4](#0-3) .
- After the controller passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same raw `params` hash to `OpenedHandler` [5](#0-4) .
- `OpenedHandler#repository` never re-checks the owner used above; it re-parses the org/repo directly from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [6](#0-5) , and `Repository.from_github_repo_name` splits that string into `owner`/`name` and does a direct lookup with no relation to `repository_owner` used for signing [7](#0-6) .
- If `provision?` is true for that (victim) repository, `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` creates a `Stack`/`ReviewStack` and a `PullRequest` record tied to the victim repository, using attacker-controlled `pull_request.head.ref`, PR number, labels, and `sender.login` [8](#0-7) [9](#0-8) .

Attacker request: a raw `POST /webhooks` with header `X-Github-Event: pull_request` and a JSON body where `repository.owner.login = "attacker-org"` (an org configured in this Shipit instance's multi-org `secrets.github` with no `webhook_secret` set) and `repository.full_name = "victim-org/victim-repo"` (a real, tracked repository with `review_stacks_enabled` and `provisioning_behavior_allow_all?`), `action: "opened"`, and a fabricated `pull_request`/`sender` block.

Why existing guards fail: `check_if_ping` and `drop_unhandled_event` don't inspect repo identity; `verify_signature` only authenticates the org named in `repository.owner.login`, not the org actually acted upon (`repository.full_name`); `ExplicitParameters` in `OpenedHandler` only validates types/presence, not cross-consistency with the verified owner; there is no model validation tying a webhook's verified org to the `Repository#owner` it mutates.

### Impact Explanation
An attacker with control of (or knowledge that a) low/no-security org is registered in a multi-org Shipit deployment can force creation of a `ReviewStack`/`Stack` and `PullRequest` for an arbitrary victim repository they do not own, without any valid signature for that victim org. This is a cross-tenant write (a payload "verified" against one organization mutating another organization's repository state), matching the Critical category "a payload for one repository mutating another's stack." The created stack subsequently enters the provisioning queue, which can trigger deploy-time command execution against the victim repository's environment/config. This is repeatable against any tracked repository configured for `review_stacks_enabled` with `allow_all`/`allow_with_label` behavior, and blast radius spans all repositories hosted by the Shipit instance, not just the attacker's own.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured in multi-organization mode (per-org sub-keys under `secrets.github`, as introduced in `CHANGELOG.md` "Support multiple GitHub organisations (#1151)"), (2) at least one org entry in that config lacking a `webhook_secret` (attacker-controlled or otherwise laxly configured), and (3) a victim repository already tracked by Shipit with review-stack auto-provisioning enabled (`allow_all`). Given these preconditions, exploitation is a single crafted HTTP POST with no GitHub interaction and no secrets — cost is trivial and fully repeatable. The main uncertainty is precondition (2), which depends on operator configuration rather than a universal default.

### Recommendation
In `OpenedHandler#repository` (and the sibling PR handlers), verify that the owner portion of `params.repository.full_name` matches the `repository_owner`/org that was actually used to authenticate the webhook (e.g., pass the verified organization through to handlers and assert equality before performing any lookup/provisioning), or have `WebhooksController#verify_signature` derive the org strictly from `full_name`'s owner segment instead of `repository.owner.login`, ensuring a single consistent source of truth is used for both signature verification and repository resolution.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (multi-org config stub):
```ruby
test "cross-org spoof: verified against attacker org, mutates victim repo" do
  Shipit.stubs(:github_default_organization).returns("attacker-org")
  Shipit.stubs(:github_app_config).with("attacker-org").returns({}) # no webhook_secret
  victim_repo = shipit_repositories(:shipit) # owner "shopify", review_stacks_enabled + allow_all
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_all)

  request.headers['X-Github-Event'] = 'pull_request'
  payload = JSON.parse(payload(:pull_request_opened))
  payload["repository"]["owner"]["login"] = "attacker-org"
  payload["repository"]["full_name"] = victim_repo.github_repo_name

  assert_difference -> { Shipit::Stack.count } do
    post :create, body: payload.to_json, as: :json
  end
  assert_response :ok
end
```
Assertions: before the request, `Shipit::Stack.where(repository: victim_repo).count == 0`; the request is verified via `attacker-org`'s (secret-less) `GitHubApp`, not `shopify`'s; after the request, a new `Shipit::Stack`/`ReviewStack` row exists under `victim_repo`, proving the equality `verified_org(attacker-org) == owner_of(full_name)(shopify)` is false yet the write still occurred.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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
