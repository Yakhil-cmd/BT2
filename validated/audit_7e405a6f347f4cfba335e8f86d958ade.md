### Title
Webhook signature verification is silently skipped when `webhook_secret` is unset, allowing unauthenticated forgery of GitHub events (including `membership`) that escalate `Shipit.github_teams` authorization - (File: lib/shipit/github_app.rb)

### Summary
This is the same trust-binding failure as the external report: a security check that is supposed to gate a privileged operation degrades to a silent no-op when a precondition (asset supports cross-chain / webhook has a secret) is absent, letting the operation proceed as if it had been validated. In `WebhooksController`, `verify_signature` delegates trust entirely to `GithubApp#verify_webhook_signature`, and that method treats "no secret configured" as "signature valid."

### Finding Description
`Shipit::WebhooksController#verify_signature` picks the GitHub App instance for the repository owner named in the *unverified* payload, and asks it to check the signature: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` is the actual gate: [3](#0-2) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

If the org's configuration has no `webhook_secret` (this is an accepted, non-error configuration value — the test fixtures ship it as `null`, e.g. `test/dummy/config/secrets.test.json` and `test/dummy/config/secrets_double_github_app.yml`), the method unconditionally returns `true`, i.e. **any** POST body is accepted as if it carried a valid HMAC from GitHub. The binding that should hold is:

`organization whose webhook_secret authenticated the request == organization the payload claims to write events for`

but when `webhook_secret` is absent, the left side of that equality is vacuously true for every request, so the equality is broken: an unauthenticated, unprivileged caller can post a payload with an arbitrary `repository.owner.login` / `organization.login` and have it processed as a legitimate GitHub-originated event, with no session, `ApiClient` token, or GitHub credential of any kind.

The consequence is not limited to data sync: `Shipit::Webhooks` processes a `membership` event by creating a `Team`/`User` on the fly and adding/removing `Membership` records, exactly as exercised in `test/controllers/webhooks_controller_test.rb`: [4](#0-3) 

`Membership` records are how `Shipit.github_teams`-based authorization is derived for users throughout the app (team-gated permissions on stacks/deploys). Forging a `membership` "added" event lets an unauthenticated attacker splice an arbitrary GitHub login into a `Shipit::Team`, and forging `push`/`status`/`check_suite` events lets them manipulate CI status, deployability, and trigger `GithubSyncJob`/`RefreshCheckRunsJob` for any stack, all without ever needing repository write access or a Shipit session.

### Impact Explanation
This crosses the required "High" bar: unauthenticated forgery of `membership` webhook events allows escalation into `Shipit.github_teams` authorization (an unprivileged remote attacker gains team membership that Shipit's permission system trusts), and forgery of `status`/`push`/`check_suite` events allows unauthenticated manipulation of stack/commit state (deployability, CI status) that gates real deploy/rollback/merge actions. No GitHub token, webhook secret, API client token, or Shipit session is required — the only precondition is that the target organization's `Shipit.github` config has `webhook_secret` unset, which the codebase treats as a normal, supported state rather than a hard failure.

### Likelihood Explanation
Likelihood is high in any deployment where `webhook_secret` is left blank for an organization (the shipped test fixtures model exactly this configuration), since `verify_webhook_signature`'s `return true unless webhook_secret` is a deliberate short-circuit reachable by any unauthenticated request to `/webhooks` (the controller only requires the `X-Github-Event` header and skips CSRF verification via `skip_before_action :verify_authenticity_token`).

### Recommendation
Fail closed instead of open: reject (422) webhook requests for organizations that have no `webhook_secret` configured, or require `webhook_secret` presence as a hard validation at `GithubApp` initialization / `Shipit.github` lookup so an org can never be routed into signature-optional handling. At minimum, `membership` handling and any team/authorization-affecting webhook events should never be trusted unless HMAC verification actually executed a comparison.

### Proof of Concept
1. Configure (or find) an organization entry in `Shipit.github` config with `webhook_secret: null` (as in `test/dummy/config/secrets.test.json`).
2. As an unauthenticated client, `POST /webhooks` with header `X-Github-Event: membership` and a JSON body such as:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "evil", "slug": "evil", "url": "https://example.com"},
  "member": {"login": "attacker"},
  "organization": {"login": "<org-with-no-webhook_secret>"}
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required.
3. `verify_signature` resolves `Shipit.github(organization: 'org-with-no-webhook_secret')`, calls `verify_webhook_signature(nil_or_garbage, raw_body)`, which returns `true` because `webhook_secret` is blank.
4. `Shipit::Webhooks.for_event('membership')` handlers run, creating/attaching `attacker` to the `Team`/`Membership` records exactly as shown in `test/controllers/webhooks_controller_test.rb` lines 129-149, granting `attacker` whatever `Shipit.github_teams`-derived authorization that team maps to — with zero credentials presented.

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
