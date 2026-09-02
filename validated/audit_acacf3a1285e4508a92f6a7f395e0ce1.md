### Title
Webhook authentication is gated by an unverified payload field, letting an unprivileged attacker forge events for organizations/repositories they do not control - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to verify the HMAC signature against by reading `repository.owner.login` / `organization.login` straight out of the **unverified** raw request body, before any signature check has succeeded. Once that lookup passes (which is a no-op whenever the selected organization has no `webhook_secret` configured — an explicitly documented, optional setting), the same untrusted body is handed unmodified to event handlers that key off *other* fields (`organization.login`, `team`, `member.login`, `repository.full_name`, etc.) to decide which `Team`, `Membership`, `Stack`, or `Repository` record to mutate. The field used to select the authentication secret and the field(s) used to select the object that is actually written are never bound together or covered by any signature, breaking the "organization authenticated == entity written" invariant, analogous to the report's price-vs-shares decoupling.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

`repository_owner` is read from `JSON.parse(request.raw_post)` — i.e. from the very payload whose signature has not yet been verified. That value determines which `GitHubApp` (and therefore which `webhook_secret`) is used to check the signature: [3](#0-2) 

`GitHubApp#verify_webhook_signature` intentionally treats an unset `webhook_secret` as "always verified":
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

`webhook_secret` is documented as optional both for single-org and multi-org (`config/secrets.yml`) deployments: [5](#0-4) [6](#0-5) 

After `verify_signature` passes (trivially, if the selected org has no secret), the controller dispatches the **same raw, attacker-controlled JSON** to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [7](#0-6) 

These handlers pick their target objects from fields that are *independent* of `repository_owner`:
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to locate a `Repository`/`Stack`, not the `owner.login` used for signature selection: [8](#0-7) 
- Membership webhooks create/attach/detach `Team`/`Membership` records keyed on `organization.login`, `team`, and `member.login` fields of the same payload (confirmed by test behavior: team/member creation and membership add/removal from webhook body): [9](#0-8) 

Because none of these target-selecting fields are covered by the same guarantee that gated the org lookup, and because the org-lookup gate itself is a no-op for any org without a `webhook_secret`, an attacker who knows (or guesses) the name of any org configured in `Shipit.github` without a secret can forge an event for a *different* org/repository/team, entirely bypassing signature verification.

### Impact Explanation
This breaks the "organization that authenticated versus the repository/entity that is written" binding explicitly called out as in-scope. The `membership` handler path is especially severe: it directly creates/removes `Membership` rows against `Shipit::Team` records, which is the exact mechanism `Authentication#force_github_authentication` uses to gate access (`current_user.authorized?` via `Shipit.github_teams`): [10](#0-9) 

An unprivileged, unauthenticated attacker can therefore forge a `membership` webhook to add an arbitrary GitHub login (their own) to a team Shipit trusts, escalating into the `Shipit.github_teams` authorization boundary — one of the explicitly listed High-impact outcomes. The same gap also lets an attacker trigger `push`/`status`/`pull_request` handlers for arbitrary tracked repositories (forcing GitHub syncs, archiving/unarchiving review stacks, writing bogus commit statuses) regardless of which org's name was used to satisfy the (no-op) signature check.

### Likelihood Explanation
Exploitability depends entirely on configuration: it requires at least one configured GitHub organization/app in `Shipit.github` to have `webhook_secret` unset — which is the officially documented default/optional state in both the example secrets file and the multi-org setup docs. Given this is a supported, non-exceptional configuration (not a misconfiguration outside the documented setup), and the webhooks endpoint (`/webhooks`) is intentionally public/unauthenticated by design, the likelihood is high for any deployment that has not explicitly set a webhook secret for every configured organization.

### Recommendation
Do not use any field from the unverified JSON body to select the verification secret. Verify the signature against every configured organization's secret (or require a stack/repository-scoped secret resolved from trusted DB state, as `Shipit::Hook`/`GithubHook` already model) before parsing/trusting any payload field, and make `webhook_secret` mandatory rather than optional, or require it for every organization in a multi-org configuration. Additionally, tie the entity acted upon by each handler to the same authenticated organization used for signature verification instead of allowing handlers to pick an independent, unverified `organization.login`/`repository.full_name`.

### Proof of Concept
Preconditions: Shipit deployed with `Shipit.github` containing at least one organization entry (e.g. `SomeOrgWithoutSecret`) whose `webhook_secret` is nil/blank (the documented default), and any `Shipit::Team`/`Shipit::Repository` tracked under a different, "protected" organization.

```
POST /webhooks HTTP/1.1
X-Github-Event: membership
Content-Type: application/json
(no X-Hub-Signature header needed)

{
  "action": "added",
  "organization": { "login": "SomeOrgWithoutSecret" },
  "team": { "id": 1, "name": "Deployers", "slug": "deployers", "url": "https://example.com" },
  "member": { "login": "attacker-handle" }
}
```
- `repository_owner` resolves to `"SomeOrgWithoutSecret"` (no `repository` key present, falls back to `organization.login`).
- `Shipit.github(organization: "SomeOrgWithoutSecret")` returns a `GitHubApp` with `webhook_secret` nil.
- `verify_webhook_signature` returns `true` unconditionally, `head(422)` is never called [4](#0-3) .
- `create` dispatches to the `membership` handler, which creates the `attacker-handle` user and a `Membership` on team `deployers` (behavior confirmed by existing handler tests) [11](#0-10) .
- If `deployers` maps to a team in `Shipit.github_teams`, `attacker-handle`'s subsequent OAuth login will now pass `current_user.authorized?` in `Authentication#force_github_authentication` [10](#0-9) , granting them access to Shipit's stacks/deploys despite never having any real GitHub team membership, Shipit session, or API token.

Note: I was unable to fully inspect `app/models/shipit/webhooks/handlers/membership_handler.rb`'s exact field parsing in this pass (only inferred from its associated tests), and cannot verify the exact production `Shipit.github` org key naming conventions used at any specific real deployment — a Devin session with full file access would be needed to confirm the exact handler code and any additional guardrails not surfaced by the index.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** test/controllers/webhooks_controller_test.rb (L129-181)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

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

    test ":membership can append an user twice" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_no_difference -> { Membership.count } do
        post :create, body: membership_params.to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can delete an user twice" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_no_difference -> { Membership.count } do
        post :create, body: membership_params.merge(action: 'removed', member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
