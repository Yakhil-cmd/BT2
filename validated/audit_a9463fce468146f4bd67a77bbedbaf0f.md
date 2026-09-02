### Title
Webhook signature verification is silently bypassed when an organization's `webhook_secret` is unset, allowing unauthenticated forgery of GitHub events (including team membership) that escalates into `Shipit.github_teams` authorization - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's credentials to use for HMAC verification from an *unverified* field of the incoming JSON body, and the actual verification method silently treats a missing `webhook_secret` as "verified = true." This mirrors the ERC-7683 analog in the report: a security-critical enforcement (there, `fillDeadline`; here, the webhook HMAC signature) is not actually enforced, letting an unprivileged, unauthenticated caller inject arbitrary webhook payloads — including `membership` events that create/modify `User`/`Team` records used by `Shipit::User#authorized?` to gate application access via `Shipit.github_teams`.

### Finding Description
`WebhooksController#verify_signature` looks up which GitHub App/organization config to use for signature verification based on `repository_owner`, which is read straight from the untrusted, not-yet-verified JSON body: [1](#0-0) [2](#0-1) 

It then delegates the actual cryptographic check to `GithubApp#verify_webhook_signature`, which unconditionally treats the request as verified whenever the resolved organization has no `webhook_secret` configured: [3](#0-2) 

Because `webhook_secret` is explicitly documented and shipped as an "optional" field in every secrets template (`config/secrets.development.example.yml`, per-org `config/secrets.development.shopify.yml`), any organization that omits it causes `verify_webhook_signature` to `return true unless webhook_secret` — i.e. the enforcement of "this request must be signed by GitHub" is dropped entirely for that org, exactly like `fillDeadline` being dropped from `fill()` in the report despite being part of the structure the check is supposed to cover.

Once `head(422)` is skipped, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` processes the attacker-supplied `params` as if it came from GitHub, including the `membership` event handler, which creates `Team`/`User` records "on the fly" purely from unsigned payload content: [4](#0-3) 

Downstream, application-level authorization is decided solely by team membership synchronized from these records: [5](#0-4) 

Binding broken: *organization whose webhook signature is verified* should equal *organization whose events (including membership/team data feeding authorization) are trusted and acted upon*. When `webhook_secret` is absent for any configured organization, that equality collapses — verification is a no-op, but the resulting `membership` event is still fully trusted to mutate `Team`/`Membership`/`User` records that gate access via `Shipit.github_teams`.

### Impact Explanation
High — this is an authentication-bypass primitive on the webhook ingestion path that can be leveraged to forge a `membership` webhook adding an attacker-controlled GitHub login to a team referenced in `Shipit.github_teams`, thereby escalating into application authorization without ever touching a real GitHub webhook secret, an `ApiClient` token, or a privileged account. It also allows forging `push`/`status`/`check_suite` events for that organization's stacks (fabricating CI state, triggering syncs), but the most severe consequence is the authorization escalation explicitly called out as High impact.

### Likelihood Explanation
Low/Medium — it requires a deployment where at least one configured GitHub organization has no `webhook_secret` set, which is an explicitly supported, documented configuration (marked "optional" in setup docs and shipped as `# nil` in every secrets template), not an operator error that deviates from documented usage. Any Shipit instance following the documented multi-org or single-org template literally, without separately deciding to add a webhook secret, is exposed.

### Recommendation
Do not treat a missing `webhook_secret` as "verification passed." `GithubApp#verify_webhook_signature` should fail closed (reject the request) when no secret is configured, or Shipit should refuse to boot/serve `/webhooks` for any organization lacking a configured `webhook_secret`. Additionally, `repository_owner` used to select the verifying organization should not be trusted until after the signature is confirmed valid.

### Proof of Concept
1. Deploy Shipit with a GitHub organization configured without a `webhook_secret` (as shown as valid/optional in `config/secrets.development.example.yml` and `config/secrets.development.shopify.yml`).
2. Send an unsigned (or arbitrarily signed) POST to `/webhooks` with header `X-Github-Event: membership` and a JSON body:
```json
{
  "organization": { "login": "<org-without-webhook_secret>" },
  "action": "added",
  "team": { "id": 999, "name": "attacker-team", "slug": "attacker-team", "url": "https://example.com" },
  "member": { "login": "attacker-github-login" }
}
```
3. `verify_signature` resolves `repository_owner` to `<org-without-webhook_secret>` (no `repository` key present, falls back to `organization.login`), calls `Shipit.github(organization: ...).verify_webhook_signature(...)`, which returns `true` immediately since `webhook_secret` is blank.
4. `Shipit::Webhooks.for_event('membership')` runs the membership handler, creating/updating the `Team` and `User` (`attacker-github-login`) records, as demonstrated in `test/controllers/webhooks_controller_test.rb` lines 129-148.
5. If `team.slug`/`name` matches an entry in `Shipit.github_teams`, `User#authorized?` (`app/models/shipit/user.rb:80-82`) will now return `true` for that forged login upon OAuth sign-in, granting application access without any legitimate GitHub team membership or webhook credential.

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

**File:** test/controllers/webhooks_controller_test.rb (L129-148)
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
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
