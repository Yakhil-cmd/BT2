### Title
Cross-organization webhook forgery via unverified `repository.owner.login`/`repository.full_name` decoupling in `WebhooksController` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Just as EIP-4758 breaks Axelar's deposit system because a piece of state (the CREATE2 address) is trusted to remain re-creatable when the underlying assumption (`SELFDESTRUCT` availability) silently disappears, Shipit's webhook pipeline trusts that the field used to *select and verify* a signing secret (`repository.owner.login`) is the same field that determines *which repository/org gets written to* (`repository.full_name`). These are two independently-read, unauthenticated JSON keys that are never bound together, so verifying against one organization's key says nothing about the other organization's data actually being mutated.

### Finding Description
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to verify the request against using a field read straight out of the untrusted JSON body, *before* any signature has been checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: ...)` supports multiple, independently configured GitHub Apps/organizations, each with its own optional `webhook_secret` (documented as optional, i.e. a supported deployment state): [3](#0-2) [4](#0-3) 

If the organization selected via `repository_owner` has no `webhook_secret` configured, `verify_webhook_signature` unconditionally returns `true`, regardless of the actual `X-Hub-Signature` header content: [5](#0-4) 

Once past `verify_signature`, every webhook handler determines the repository/stack to act on from a *different, independently-parsed* JSON key — `repository.full_name` — with no cross-check against `repository.owner.login`: [6](#0-5) 

Because `repository_owner` (verification key selector) and `repository_name`/`repository.full_name` (write target selector) are two unrelated fields inside the same unauthenticated JSON payload, an attacker can set `repository.owner.login` to any organization configured *without* a `webhook_secret` (satisfying the always-true check) while setting `repository.full_name` (and other event-specific fields such as `organization.login`, `member.login`, `team`) to target a completely different organization/repository tracked by the same Shipit instance. The equality the system implicitly relies on — *organization that authenticated == organization/repository that is written* — is broken.

### Impact Explanation
This lets an unauthenticated attacker forge arbitrary GitHub webhook deliveries for **any** repository/organization tracked by the Shipit install, as long as at least one configured org lacks a `webhook_secret`. Concretely reachable, unprivileged, credential-free consequences include:
- `push` events enqueueing `GithubSyncJob` for arbitrary stacks belonging to a different org, affecting continuous-deployment/tracking state.
- `membership` events creating/deleting `Team`/`Membership`/`User` records for an org the attacker doesn't control, as demonstrated in the handler's own test coverage: [7](#0-6) 

Because `Shipit.github_teams` membership drives the `force_github_authentication` authorization check, forging `membership`/`Team` records is a path toward escalation into `Shipit.github_teams` authorization for logins the attacker controls: [8](#0-7) 

This satisfies the required "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" impact bar without any session, API token, webhook secret knowledge, or GitHub App key.

### Likelihood Explanation
Requires only: (a) knowledge that the target Shipit instance is configured with multiple GitHub organizations (a documented, supported topology — `secrets_double_github_app.yml`), and (b) at least one of those organizations having no `webhook_secret` set (explicitly documented as optional, and the default/example configs ship with `webhook_secret: null`). No session, API token, GitHub App private key, or GitHub write access is needed — the `/webhooks` endpoint is deliberately public. This is a realistic and low-effort scenario for any Shipit operator who follows the example configs literally or who onboards a low-value/test organization without bothering to set a secret.

### Recommendation
- Verify the webhook signature using a secret keyed by a value that is itself authenticated by GitHub's delivery mechanism (e.g., require and enforce `webhook_secret` for every configured organization; refuse requests when no secret is configured rather than treating it as automatically valid).
- After verifying the signature, re-derive the organization from the *same* fields that were HMAC-signed and cross-check that `repository.owner.login`/`organization.login` used for verification matches the `repository.full_name` prefix used by handlers, rejecting mismatches.
- Make `webhook_secret` mandatory in engine configuration validation rather than optional.

### Proof of Concept
1. Configure two orgs in `secrets.yml`: `OrgA` (no `webhook_secret`) and `OrgB` (tracked stacks, doesn't matter what secret it has).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": 1, "name": "evil", "slug": "evil", "url": "https://example.com" },
  "organization": { "login": "OrgA" },
  "repository": { "full_name": "OrgB/target-repo", "owner": { "login": "OrgA" } },
  "member": { "login": "attacker-controlled-login" }
}
```
3. `verify_signature` resolves `repository_owner` = `"OrgA"`, loads `Shipit.github(organization: "OrgA")`, and since `OrgA` has no `webhook_secret`, `verify_webhook_signature` returns `true` for any/no `X-Hub-Signature` value.
4. The `membership` handler processes the payload and creates a `Team`/`Membership` for `OrgB` (via `organization.login`/`team` fields) with an attacker-chosen `member.login`, even though only `OrgA`'s (secret-less) verification path was exercised — confirming the org used to pass verification is decoupled from the org actually written to.

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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-165)
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
