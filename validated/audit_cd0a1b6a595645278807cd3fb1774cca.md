### Title
Query-string parameters can be used to select a different GitHub organization's webhook config than the one that actually signed the request, letting a blank `webhook_secret` bypass signature verification for events acted on a different repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` chooses which organization's webhook secret to verify against by reading `repository_owner` from Rails' `params`, while the actual signature comparison is always performed over `request.raw_post` [1](#0-0) . Because Rails merges query-string parameters over JSON body parameters at the top level (`request_parameters.merge(query_parameters)`), an attacker can override the `repository` key entirely via the query string, causing `repository_owner` (and therefore which org's `webhook_secret` is used) to diverge from the organization whose repository is actually acted upon in `create`, where the body is independently re-parsed from `request.raw_post` [2](#0-1) [3](#0-2) .

### Finding Description
This is the "organization that authenticated versus the repository that is written" trust binding. The invariant should be: `org(signature verified) == org(repository written)`.

- `verify_signature` picks the GitHub app config via `Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against `request.raw_post` using that org's secret [1](#0-0) .
- `repository_owner` is computed from `params.dig('repository', 'owner', 'login')` [3](#0-2) , i.e., the standard `ActionController::Parameters`, not the raw signed body.
- `create` re-parses the actual payload directly from `request.raw_post` via `JSON.parse` and dispatches to handlers using that independently-parsed hash [2](#0-1) .
- `Shipit::GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for the selected org: `return true unless webhook_secret` [4](#0-3) .
- `Shipit.github_app_config` looks up the org purely by name from `secrets.github`, and `Shipit.github` will construct a `GitHubApp` for whatever organization key is passed [5](#0-4) . Multi-org deployments are an explicitly supported configuration shape, as shown in the sample multi-org secrets file with a `webhook_secret: # nil` entry per org [6](#0-5) .

Because Rails' `ActionDispatch::Http::Parameters#parameters` merges `query_parameters` over `request_parameters` for identical top-level keys, an attacker who appends `?repository[owner][login]=some_org_without_secret` to the webhook URL can force `repository_owner` (used only in `verify_signature`) to name an organization whose `webhook_secret` is unset, while the JSON body actually processed by `create` (parsed fresh from `raw_post`, unaffected by the query string) can reference any tracked repository/stack belonging to any organization configured in this Shipit instance. The signature check therefore verifies nothing meaningful for the repository actually being acted upon.

### Impact Explanation
An unauthenticated, unprivileged attacker who has no GitHub webhook access and no knowledge of any `webhook_secret` can forge arbitrary GitHub webhook events against any repository/stack tracked by the Shipit instance, as long as at least one configured organization in `secrets.github` lacks a `webhook_secret` (a documented/valid configuration, e.g., in `config/secrets.development.shopify.yml`). This includes:
- Forging `membership` events to add themselves to a `Team` mapped into `Shipit.github_teams`, which is used to authorize application access (`app/controllers/concerns/shipit/authentication.rb`'s `current_user.authorized?` checks team membership) — escalation into authorization.
- Forging `status`/`check_suite`/`push` events to manipulate commit statuses, merge status, or trigger sync jobs for stacks/repositories that have nothing to do with the org whose (missing) secret was used to pass verification.

This maps to the High-severity bucket ("escalation into `Shipit.github_teams` authorization") and, depending on downstream gating logic (deploy/merge status checks), could contribute to an unauthorized deploy.

### Likelihood Explanation
Requires only that the deployment: (1) is multi-org (`secrets.github` has more than one org key, which the engine explicitly supports and documents), and (2) at least one configured org has a blank/unset `webhook_secret` — a state the code explicitly tolerates (`return true unless webhook_secret`). No credentials, tokens, or prior access are needed; the attacker only sends an unauthenticated HTTP POST with a crafted query string.

### Recommendation
Determine `repository_owner` (and thus which org's secret to verify with) from the same freshly-parsed `JSON.parse(request.raw_post)` body used in `create`, never from `ActionController::Parameters`, which is subject to query-string precedence over body-parsed JSON. Additionally, verify that the organization used to select the webhook secret matches the organization of the repository actually acted upon before dispatching to handlers, and consider rejecting webhooks entirely for any organization configured with a blank `webhook_secret` rather than treating it as "always verified."

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `orgA` (has a repository tracked in Shipit, `webhook_secret` set) and `orgB` (no `webhook_secret` configured), per `config/secrets.development.shopify.yml`.
2. Attacker sends:
```
POST /webhooks?repository[owner][login]=orgB
X-Github-Event: membership
Content-Type: application/json

{"action":"added","team":{"id":1,"name":"...","slug":"..."},"organization":{"login":"orgA"},"member":{"login":"attacker-github-login"}}
```
No valid `X-Hub-Signature` is required.
3. `verify_signature` computes `repository_owner` as `"orgB"` from the query string (overriding the body's `organization.login: "orgA"` at the merged-params level) [3](#0-2) , looks up `orgB`'s `GitHubApp`, and since `orgB.webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally [4](#0-3) .
4. `create` re-parses `request.raw_post` (unaffected by the query string) and dispatches the membership event against `orgA`'s team, adding the attacker's GitHub login as a member — as exercised by the existing test `":membership creates the mentioned user on the fly"` / `":membership can append an user membership"` [7](#0-6) , but here driven entirely by an unauthenticated, unsigned attacker request.

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

**File:** test/controllers/webhooks_controller_test.rb (L142-165)
```ruby
    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can delete an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, -1 do
        post :create, body: membership_params.merge(action: 'removed').to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can append an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end
```
