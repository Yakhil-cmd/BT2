### Title
Webhook signature check is bypassed when an organization has no `webhook_secret`, allowing forged `membership` events to add an attacker-controlled GitHub login to `Shipit.github_teams` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This is the same bug class as the Aave `claimToTreasury` report: a critical guard (a "this must not be empty/zero" check) is missing before an authorization-relevant side effect is performed. In Aave, `treasuryVault` was never checked for `address(0)` before transferring funds. In Shipit, `Shipit::GitHubApp#verify_webhook_signature` never checks that `webhook_secret` is present before treating the request as "authenticated" — it explicitly treats a blank secret as an automatic pass. Combined with the fact that the "organization" used to select which secret to check is itself taken from the unauthenticated payload, this breaks the binding: *the organization that authenticated the webhook* must equal *the organization whose data the handler subsequently trusts and writes*.

### Finding Description
The webhook signature check is: [1](#0-0) 

`repository_owner` (used to pick which `GitHubApp` — and therefore which `webhook_secret` — to validate against) is derived from the unauthenticated JSON body itself, with a documented fallback to the `organization` sub-object when `repository` is absent: [2](#0-1) 

The actual signature check is: [3](#0-2) 

`return true unless webhook_secret` means that for any GitHub organization configured in `Shipit.github` **without** a `webhook_secret` (an explicitly supported configuration — see `test/dummy/config/secrets.test.json` and the development secrets templates, both of which ship with `webhook_secret: null`), `verify_signature` accepts *any* payload, without ever checking the `X-Hub-Signature` header content. [4](#0-3) 

Because `repository_owner` is read straight out of the attacker-supplied JSON body, an unauthenticated caller can simply set `organization.login` (or `repository.owner.login`) to the name of any org configured with a blank `webhook_secret`, and the request sails through `verify_signature` regardless of the real signing secrets used by other (properly configured) organizations. Once inside `create`, the actual entity acted upon is derived from a *different* field of the same attacker-controlled payload — `repository.full_name` in `Handler#repository_name`/`#stacks`, or `organization`/`team`/`member` in the membership flow — with no re-validation that this data actually originated from the organization that "authenticated" the request: [5](#0-4) 

The `:membership` webhook path (exercised in the test suite) creates `Team` and `User` records directly from payload fields (`team`, `organization`, `member`) with no cross-check against the organization used for signature verification: [6](#0-5) [7](#0-6) 

If the attacker's own GitHub login is added as a member of a `Team` whose `slug`/`handle` matches an entry in `Shipit.github_teams`, `User#authorized?` — which gates all UI/API access — will return `true` for that user: [8](#0-7) 

### Impact Explanation
This breaks the binding "organization that authenticated versus the repository/entity that is written." An unprivileged, unauthenticated caller can:
1. Cause writes to any tracked `Stack`/`Repository`/`Team`/`User` record (push-triggered `GithubSyncJob`, `ReviewStack` creation/archival, commit statuses, check-run refreshes) by simply naming an org with a blank `webhook_secret`, regardless of which org actually owns the target repository.
2. In the membership flow, forge team-membership webhooks to insert an attacker-chosen GitHub login into a `Team` matching `Shipit.github_teams`, escalating that login into the authorized-user set gated by `force_github_authentication`/`User#authorized?`.

This matches the "High" impact category: escalation into `Shipit.github_teams` authorization, plus unauthorized cross-repository writes to Shipit's own state (stacks, teams, statuses) without any credential.

### Likelihood Explanation
Likelihood is directly tied to operational configuration: any Shipit deployment that (a) supports multiple GitHub organizations (a documented, supported configuration — see `docs/setup.md`'s "Using Multiple Github Applications" section) and (b) leaves `webhook_secret` blank for at least one of them (also an explicitly supported/documented value, shown as `# nil` in every example secrets file in the repo) is exploitable by any internet client able to reach `/github/webhooks`, with zero credentials, tokens, or prior access. The webhook endpoint is deliberately unauthenticated (`ActionController::Base`, no `Shipit::Authentication`), so the only gate is `verify_signature`, which this logic defeats.

### Recommendation
- In `Shipit::GitHubApp#verify_webhook_signature`, never implicitly trust a request when `webhook_secret` is blank; either require a non-blank secret for every configured organization at boot, or refuse (`head 422`) requests for organizations lacking a secret instead of returning `true`.
- Do not let `repository_owner` (used only to select the verifying key) be treated as authoritative for the entity being written to. After signature verification succeeds, cross-check that the organization used to select the secret matches the organization implied by `payload['repository']['full_name']` (and any `team`/`organization`/`member` fields used by handlers such as the membership flow) before performing any DB writes.
- Add a startup/config validation that warns or fails if any org in `Shipit.github` config lacks a `webhook_secret` in non-development environments.

### Proof of Concept
Given a multi-org Shipit deployment where `OrgB` has `webhook_secret: nil` (a supported configuration) and `OrgA` (the real owner of `important/repo`) has a real, unknown-to-attacker webhook secret:

```
POST /github/webhooks
X-Github-Event: membership
X-Hub-Signature: sha1=anything-or-omitted

{
  "action": "added",
  "team": { "id": 1, "name": "Deployers", "slug": "deployers", "url": "https://example.com" },
  "organization": { "login": "OrgB" },
  "member": { "login": "attacker-github-login" }
}
```

Because `repository_owner`/`organization.login` resolves to `OrgB`, whose `webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`) without checking `X-Hub-Signature`. The membership handler then creates/updates the `Team` and adds `attacker-github-login` as a member (`test/controllers/webhooks_controller_test.rb:129-140`), matching `test/models/users_test.rb` behavior. If `"deployers"` matches a team in `Shipit.github_teams`, the attacker's GitHub account becomes `authorized?` per `app/models/shipit/user.rb:80-82`, without needing OrgA's secret, a Shipit session, or any API token — even though the compromised action concerns/could be aimed at repositories under the properly-secured `OrgA`.

*Note:* I could not fully retrieve the exact source of `Shipit::Webhooks::Handlers::MembershipHandler` (tool access was cut off before I could load it), so the precise field-by-field logic of that specific handler is inferred from its test coverage rather than directly cited; a Devin session with full file access should verify that handler's implementation to confirm it does not perform any additional organization/team cross-check beyond what `webhooks_controller.rb` already fails to enforce.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L55-60)
```ruby
    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
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

**File:** test/dummy/config/secrets.test.json (L7-13)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S\n73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG\nM0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv\nibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu\npQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s\nGu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1\nu0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM\nTZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b\nqicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og\nqRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI\nRsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b\ngg9PFCkCgYEA+7u8A0l0C ... (truncated)
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

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
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
```

**File:** test/controllers/webhooks_controller_test.rb (L208-210)
```ruby
    def membership_params
      { action: 'added', team: team_params, organization: { login: 'shopify' }, member: { login: 'walrus' } }.merge(repository_params)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
