### Title
Unsigned GitHub webhooks are fully trusted when `webhook_secret` is unset, allowing unauthenticated forgery of `membership`, `push`, `status`, and other events - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController` selects a GitHub App configuration purely from attacker-supplied payload fields and then delegates trust entirely to `GithubApp#verify_webhook_signature`. When that App's `webhook_secret` is blank/nil (a documented, valid configuration state), signature verification is skipped entirely and the raw, unauthenticated payload is treated as a legitimate GitHub event.

### Finding Description
`WebhooksController#verify_signature` resolves which `GithubApp` instance to use for verification from unauthenticated request data: [1](#0-0) [2](#0-1) 

`repository_owner` is read directly from `params.dig('repository', 'owner', 'login')` (or `organization.login`) — a field inside the very payload that is supposed to be authenticated. It is then used to pick which `GithubApp` config (and thus which `webhook_secret`) governs verification of the same request.

`GithubApp#verify_webhook_signature` then does: [3](#0-2) 

`return true unless webhook_secret` means that if the resolved organization's config has no `webhook_secret` configured (nil is a documented, supported value — see `test/dummy/config/secrets.test.json` `"webhook_secret": null` and `docs/setup.md`/`config/secrets.development.shopify.yml` templates showing `webhook_secret: # nil`), **every** payload claiming to belong to that org is accepted as verified with zero cryptographic proof of origin.

This breaks the trust binding: *the organization whose config is selected to "authenticate" the request* ≠ *any cryptographic guarantee that the request actually originated from GitHub for that organization*. The payload field (`repository.owner.login`) that selects the trust boundary is never itself covered by a signature check when the secret is absent — it's a self-selecting, self-verifying field.

Once past `verify_signature`, `WebhooksController#create` dispatches the entire attacker-controlled payload to registered handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) 

Handlers such as the `membership` event handler directly mutate authorization-relevant state in the local database (creating `Team`/`User`/`Membership` records) based solely on this unauthenticated payload, as shown by test coverage: [5](#0-4) 

Crucially, application authorization is derived purely from these locally-persisted `Membership`/`Team` rows, not from a live GitHub check at login time: [6](#0-5) 

### Impact Explanation
An unprivileged, unauthenticated internet attacker who knows (or guesses) the name of an organization configured in Shipit without a `webhook_secret` can POST a forged `membership` webhook granting themselves (their real GitHub login/id) membership in one of `Shipit.github_teams`. They can then complete a normal GitHub OAuth login as themselves, and `current_user.authorized?` will now return true purely because of the forged local `Membership` row — granting them full access to trigger deploys, rollbacks, and merges. This is an authentication/authorization bypass leading to unauthorized deploys, which is explicitly listed as a Critical/High-severity outcome in scope. The same unsigned-webhook path can also forge `push`, `status`, `check_suite`, `pull_request`, etc., corrupting commit/deploy state for any stack, independent of the membership escalation.

### Likelihood Explanation
This requires no session, no `ApiClient` token, and no `webhook_secret`/`api_clients_secret` knowledge — it is triggerable by any unauthenticated network client, provided the deployment leaves `webhook_secret` unset for at least one configured organization. This is a realistic and even encouraged default in the repo's own example configs (`webhook_secret: # nil` appears in multiple committed config templates), making misconfiguration likely rather than exotic.

### Recommendation
Do not trust unauthenticated payload fields to select the verification context, and never silently skip signature verification. `verify_webhook_signature` should fail closed (return `false`/reject the webhook) when `webhook_secret` is not configured for the resolved organization, rather than treating a missing secret as an implicit "trust everything" bypass. Additionally, authorization-sensitive mutations (team/membership changes) driven by webhooks should be treated as advisory caches refreshed from a live, authenticated GitHub API call rather than sole authority for `User#authorized?`.

### Proof of Concept
1. Configure (or find a deployment with) an organization entry in `config/secrets.yml` with `webhook_secret: nil` (a state directly demonstrated as valid in `test/dummy/config/secrets.test.json` and `docs/setup.md`).
2. As an anonymous attacker, `POST /webhooks/github` (whatever route the engine mounts `WebhooksController` at) with header `X-Github-Event: membership` and a JSON body:
```json
{
  "action": "added",
  "organization": {"login": "<the-secretless-org>"},
  "team": {"id": 1, "name": "Required Team", "slug": "required-team", "url": "https://example.com"},
  "member": {"login": "attacker-github-login"}
}
```
No `X-Hub-Signature` header is required to pass — `GithubApp#verify_webhook_signature` returns `true` immediately because `webhook_secret` is blank, per `lib/shipit/github_app.rb:76-83`.
3. The `membership` handler creates the `Team`/`Membership` records exactly as shown by `test/controllers/webhooks_controller_test.rb:129-149`.
4. Attacker completes a normal GitHub OAuth login through `GithubAuthenticationController#callback` as themselves; `User#authorized?` (`app/models/shipit/user.rb:80-82`) now finds the forged `Membership` and returns `true`, granting full access to deploy/rollback/merge actions.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
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

**File:** test/controllers/webhooks_controller_test.rb (L129-149)
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
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
