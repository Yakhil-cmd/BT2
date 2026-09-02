### Title
Unauthenticated GitHub webhook forgery escalates into `Shipit.github_teams` authorization when `webhook_secret` is unset - (File: `lib/shipit/github_app.rb`)

### Summary
`Shipit::GithubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for an organization, so `WebhooksController#verify_signature` never validates the authenticity of the payload in that (documented, default) configuration. This breaks the trust binding `organization that GitHub authenticated (via HMAC) == organization the engine acts on behalf of`, letting anyone POST a forged `membership` event that creates arbitrary `Team`/`User` records and grants team membership, which is exactly the input `User#authorized?` uses to gate the whole application (deploy, rollback, hooks, tasks).

### Finding Description
`WebhooksController#create` processes any incoming webhook payload by dispatching it to the handlers registered for the `X-Github-Event` header, but only after `before_action :verify_signature`: [1](#0-0) 

The verification logic delegates to `GithubApp#verify_webhook_signature`: [2](#0-1) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

If `@webhook_secret` (`config[:webhook_secret]`) is blank — which is the value shown for `webhook_secret` in both shipped example configs — the method returns `true` regardless of the `X-Hub-Signature` header or payload contents: [3](#0-2) [4](#0-3) 

This means the binding the design intends — "this webhook truly originated from the GitHub organization it claims (`repository_owner`)" — collapses to "always true" whenever an operator leaves `webhook_secret` unset (the documented default). An unauthenticated network client can then POST directly to the `/webhooks` route with any `X-Github-Event` header and arbitrary JSON body, and it will be treated as a legitimate GitHub event.

One of the dispatched event types is `membership`, whose handler creates the referenced `Team` and `User` on the fly and adds the member to the team, as shown by the existing test coverage: [5](#0-4) 

`User#authorized?` — the single gate enforced by `Shipit::Authentication#force_github_authentication` for the entire UI/session-based surface — is defined purely in terms of team membership: [6](#0-5) [7](#0-6) 

Because forged `membership` webhooks can create/attach arbitrary `Team`/membership rows without any GitHub org signature check, an attacker who can already complete GitHub OAuth login (any GitHub account, not necessarily a member of the required org/team) can forge a `membership` webhook that adds their own `User` record to a `Team` matching one of `Shipit.github_teams`, then satisfy `authorized?` and gain full access to every stack/deploy/rollback/task/hook action gated behind `force_github_authentication`.

### Impact Explanation
This is an escalation into `Shipit.github_teams` authorization — explicitly listed as a High-severity impact category. Once `authorized?` is satisfied via the forged membership, the attacker's session behaves as a fully authorized Shipit user and can trigger deploys/rollbacks (`Stack#trigger_deploy`, `Stack#trigger_task`), which can lead to unauthorized deploys/rollbacks — a Critical-tier outcome — since those actions are otherwise only available to users vetted through the GitHub-team check.

### Likelihood Explanation
The precondition is that the deployment does not set `webhook_secret` for the relevant GitHub organization config. This is the value shown in both shipped example secrets files (`webhook_secret: # nil`), so it is a plausible, in-scope, documented configuration state rather than a misuse of the engine's contract — the engine itself silently downgrades to "no verification" instead of failing closed. Given that, the attack requires no privileged credentials: no `ApiClient` token, no `webhook_secret`, no GitHub App private key — only network access to the `/webhooks` endpoint and completion of the normal (unprivileged) GitHub OAuth login flow that any GitHub account can complete.

### Recommendation
Fail closed instead of failing open in `GithubApp#verify_webhook_signature`: if no `webhook_secret` is configured, reject the webhook (or require operators to always configure a secret, refusing to boot/mount the engine without one) rather than treating unsigned payloads as verified. Additionally, cross-check that the `repository_owner`/`organization` used to select the app for verification actually matches the entity that the resulting handler acts upon, and disallow the `membership`/team-mutating handlers from being reachable without the signature check having concretely authenticated against a real, secret-holding organization.

### Proof of Concept
Preconditions: Shipit instance has an org configured under `Shipit.github` without a `webhook_secret` (e.g., using `config/secrets.development.example.yml`/`config/secrets.development.shopify.yml` as shipped, `webhook_secret: # nil`).

1. Attacker logs in through the normal `/github/auth/github` OAuth flow with any (non-member) GitHub account, obtaining a `session[:user_id]` for their own unauthorized `User` (per `GithubAuthenticationController#callback`).
2. Attacker sends an unauthenticated request:
   ```
   POST /webhooks
   X-Github-Event: membership
   Content-Type: application/json

   {
     "action": "added",
     "organization": { "login": "<configured-org>" },
     "team": { "id": 999, "name": "Developers", "slug": "developers", "url": "https://example.com" },
     "member": { "login": "<attacker-github-login>" }
   }
   ```
   Because `webhook_secret` is unset for `<configured-org>`, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`), so `verify_signature` never halts the request, regardless of the (absent/incorrect) `X-Hub-Signature` header.
3. The `membership` handler creates the `Team` and finds/creates the `User` for `<attacker-github-login>`, adding the membership (as shown by `test ":membership creates the mentioned team on the fly"` / `test ":membership creates the mentioned user on the fly"`).
4. Attacker's `User#authorized?` now returns `true` because `teams.where(id: Shipit.github_teams.map(&:id)).exists?` matches the forged team, bypassing the intended GitHub-team gate enforced by `force_github_authentication`.
5. Attacker now has full session access to trigger deploys/rollbacks/tasks on any stack.

Note: I was unable to view the exact source of the `membership` webhook handler file (under `app/models/shipit/webhooks/handlers/`) within the index; the described handler behavior is inferred from the passing test assertions in `test/controllers/webhooks_controller_test.rb`. For full verification of the exact handler logic (e.g., whether the organization association is separately validated), a Devin session with full repository access would be needed.

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

**File:** config/secrets.development.shopify.yml (L5-9)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
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
