### Title
Cross-tenant webhook authorization bypass: signature verification org ≠ payload-processed repository org - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook by looking up the `GitHubApp`/`webhook_secret` for the organization taken from `params.dig('repository','owner','login')`, but every pull_request handler (e.g. `ClosedHandler#repository`) resolves the target `Repository` from the independent field `params.repository.full_name`. Nothing binds these two values together, so a signature that is valid for organization A's secret can be attached to a payload whose `repository.full_name` names a repository belonging to organization B, letting the handler mutate B's `ReviewStack`/`Stack`.

### Finding Description
The broken binding, stated as an equality that the code never enforces:

`organization_whose_secret_verified(body) == organization_named_in(params.repository.full_name)`

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and fetches the matching app via `Shipit.github(organization: repository_owner)`, then HMACs the **raw body** against that org's `webhook_secret`: [1](#0-0)  and [2](#0-1) 
- Once verified, `create` blindly dispatches the *entire parsed body* to every registered handler for the event, with no re-check of which org's secret was used: [3](#0-2) 
- `Handler#repository_name`/`#stacks` (base class) and every `PullRequest::*Handler#repository` (e.g. `ClosedHandler`) resolve the acted-upon `Repository` from `params.repository.full_name`, a completely separate JSON field from `repository.owner.login`: [4](#0-3)  and [5](#0-4) 
- `Repository.from_github_repo_name` does a plain DB lookup by whatever owner/name are embedded in `full_name`, independent of which org's secret authenticated the request: [6](#0-5) 

In a multi-tenant deployment (`docs/setup.md`, "Using Multiple Github Applications", and `test/dummy/config/secrets_double_github_app.yml`), `Shipit.github_app_config(organization)` picks a distinct `webhook_secret` per top-level org key: [7](#0-6) . Because `verify_signature` only proves "this body was signed with organization X's secret," and the handlers never confirm that `repository.full_name`'s owner equals `repository_owner`/X, a party in legitimate possession of *their own* org's webhook secret can freely set `repository.full_name` to `"victim-org/victim-repo"` in the same JSON body they sign, and the signature will still validate (HMAC is computed over the full attacker-controlled raw body with the attacker's own known secret). `ClosedHandler#process` then calls `review_stack.archive!` against the victim org's repository/`ReviewStack`, and other pull_request handlers (`OpenedHandler`, `LabeledHandler`, etc.) similarly provision/archive/unarchive stacks for the victim repo.

No existing guard prevents this: `drop_unhandled_event` only checks the event name exists; `ExplicitParameters` only validates shape/types of `params.repository.full_name`, not that it matches `repository_owner`; there is no `Repository`-level check tying the verified organization to the acted-upon repository.

### Impact Explanation
An attacker who legitimately controls one org/tenant onboarded onto a shared multi-org Shipit instance (and therefore knows only their own webhook secret) can forge pull_request events that mutate any *other* tenant's tracked repository state: archive/unarchive review stacks, trigger provisioning (`OpenedHandler`), or update pull request metadata for repositories they have no authorization over. This is a cross-tenant write primitive — "a payload for one repository mutating another's stack" — matching the Critical impact category (authentication bypass allowing a valid signature for repo A to authorize a write against repo B's data), and is repeatable against any repository row that exists in the Shipit database, across all tenants sharing the instance.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`Shipit.github` keyed by org, as documented) where the attacker is a legitimate admin/owner of at least one onboarded org (and thus knows that org's `webhook_secret`, which is expected/normal for them) but not of the victim org. Given that precondition, the attack costs nothing beyond crafting one JSON POST with mismatched `repository.owner.login` vs `repository.full_name` and a correctly computed HMAC using the attacker's own known secret — fully repeatable and scriptable.

### Recommendation
Bind the verified organization to the repository actually processed: after signature verification, ensure `params.dig('repository','full_name').split('/').first.casecmp(repository_owner) == 0` (or equivalent) before dispatching to handlers, or pass the verified `repository_owner`/`GitHubApp` context into handlers and have `Repository.from_github_repo_name` (or the handler base class) reject/ignore repositories whose owner does not match the organization whose secret validated the request.

### Proof of Concept
Minitest plan (controller test, extending `test/controllers/webhooks_controller_test.rb` style):
```ruby
test "signature valid for org A does not authorize mutating org B's repository" do
  victim_repo = shipit_repositories(:shipit) # owner: "shopify" per fixtures
  victim_stack = create_stack_for(victim_repo) # not_archived

  attacker_org = "attacker-org"
  payload = JSON.parse(payload(:pull_request_closed))
  payload["repository"]["owner"]["login"] = attacker_org      # side A: org whose secret is used for verification
  payload["repository"]["full_name"] = victim_repo.github_repo_name # side B: org acted upon by ClosedHandler

  # attacker legitimately possesses attacker-org's own webhook secret
  Shipit.github(organization: attacker_org).stubs(:verify_webhook_signature).returns(true)

  @request.headers['X-Github-Event'] = 'pull_request'
  assert_difference -> { victim_stack.reload; Shipit::Stack.not_archived.count }, -1 do
    post :create, body: payload.to_json, as: :json
  end
  assert_response :ok
  assert victim_stack.reload.archived?, "expected victim org's stack to be archived despite signature belonging to attacker-org"
end
```
Assertions on both sides of the binding: `payload["repository"]["owner"]["login"]` (verified side, = `"attacker-org"`) must differ from `payload["repository"]["full_name"].split("/").first` (acted-upon side, = `"shopify"`), and the test shows the request still succeeds (`assert_response :ok`) and mutates `victim_stack`, proving the binding is not enforced.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

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
