### Title
Webhook organization spoofing lets an attacker forge writes to a victim repository using a different organization's webhook secret — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC `webhook_secret`) to verify a webhook against using an attacker-controlled field taken straight from the *unverified* JSON body (`repository.owner.login`), while the handler that actually mutates state resolves the target `Stack`/`Commit` using a different, independently-controlled field of the same forged body (`repository.full_name`). In a multi-organization Shipit deployment these two values are never cross-checked, so a request can be "authenticated" against organization A's secret while its side effects are applied to organization B's repository.

### Finding Description
`verify_signature` computes the organization to authenticate against purely from the raw, unverified payload: [1](#0-0) [2](#0-1) 

That organization is then used to fetch the `GitHubApp` (and its `webhook_secret`) via `Shipit.github(organization:)`, which in the documented multi-org config schema looks up a distinct secret per organization key: [3](#0-2) 

Signature verification itself trivially passes when the resolved organization has no `webhook_secret` configured at all — a state explicitly supported by the setup docs/example configs (`webhook_secret: # nil`): [4](#0-3) [5](#0-4) 

Once `verify_signature` passes, `create` dispatches the *same forged payload* to event handlers, which resolve the target repository/stack from a **different** field of the payload — `repository.full_name` — with no re-check that it belongs to the organization that was just authenticated: [6](#0-5) [7](#0-6) [8](#0-7) 

This breaks the binding: **organization that authenticated == organization whose repository is written**. An attacker can set `repository.owner.login` to an organization with no configured `webhook_secret` (or one whose secret they know because they legitimately administer that tenant's GitHub App), sign the request accordingly (or send no valid signature at all if the secret is unset), and set `repository.full_name` to `victim-org/some-repo`, a repository belonging to a completely different, properly-secured organization. Handlers such as `PushHandler` and `StatusHandler` then act on the victim's `Stack`/`Commit` records as if the request had been validated with the victim's own secret: [9](#0-8) [10](#0-9) 

The existing test suite confirms the organization used for verification comes straight from the payload, independent of any binding to the acted-upon repository: [11](#0-10) 

### Impact Explanation
An attacker who controls (or can forge under an unsecured org's identity) a webhook signature for **any** organization configured on the Shipit instance can inject a forged event that is applied to **any other organization's repository/stack** tracked by that same Shipit install, since resolution to a `Stack` only depends on `repository.full_name`, not on the authenticated organization. This yields cross-repository writes: forging fake commit statuses (`StatusHandler#process` → `Commit#create_status_from_github!`) that could satisfy merge/deploy gating checks, or forcing `PushHandler#process` → `Stack#sync_github(expected_head_sha:)` against an attacker-chosen SHA for a victim stack. This matches the "cross-repository writes" / "unauthorized deploy" impact class.

### Likelihood Explanation
This requires a Shipit instance configured with the documented multi-organization GitHub App schema (a supported, in-scope configuration, not a deviation from how the engine is meant to be mounted) and either (a) at least one configured organization with `webhook_secret` unset — fully unprivileged, zero secret knowledge needed — or (b) the attacker legitimately administering the GitHub App/webhook secret of any one tenant organization on a shared Shipit instance and using it to attack a different tenant's repository. Both are realistic in shared/multi-tenant deployments, which the engine explicitly documents and supports.

### Recommendation
Bind the verified organization to the repository actually acted upon: after `verify_webhook_signature` succeeds, ensure the organization used for verification matches the owner of `repository.full_name` (or, more robustly, resolve the target `Repository`/`Stack` first and verify the signature using that repository's own organization's secret, rejecting requests where they disagree). Also consider disallowing organizations with a blank `webhook_secret` from unconditionally passing verification when the deployment has other organizations configured with secrets.

### Proof of Concept
1. Configure Shipit with two organizations: `attacker-org` (no `webhook_secret`, or one you control) and `victim-org` (has a stack tracking `victim-org/prod-repo`, secret unknown to attacker).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/prod-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and, since that org has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally — no valid `X-Hub-Signature` for `victim-org` is ever required.
4. `create` dispatches the payload to `PushHandler`, which resolves the stack via `repository.full_name = "victim-org/prod-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
