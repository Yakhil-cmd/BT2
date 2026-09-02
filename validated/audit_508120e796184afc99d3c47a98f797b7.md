### Title
Webhook signature verification is keyed off an attacker-controlled field disconnected from the repository payload it authorizes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to validate the request against using a field read directly out of the untrusted JSON body, and that same body (in full) is later dispatched to event handlers that act on whatever `repository` object it contains. The two are never cross-checked, so the "organization whose secret authenticated the request" can be made to diverge from the "repository the handlers actually write to," exactly the class of binding failure described in the source report (a check computed on one derived value while the state-mutating logic consumes a different, uncorrelated value from the same input).

### Finding Description
`verify_signature` derives `repository_owner` from the raw, unauthenticated payload before any signature has been checked, then uses it to look up the `GitHubApp` (and therefore the `webhook_secret`) that will be used for the HMAC comparison: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: ...)` config allows independent, optional `webhook_secret` per organization; when unset for a given org, `verify_webhook_signature` short-circuits to `true` without ever computing an HMAC: [3](#0-2) 

This is a documented, legitimate configuration (multi-org setups, or an org onboarded before a secret is configured): [4](#0-3) 

After `verify_signature` passes, `create` parses the entire raw body and hands it, unmodified, to the event handlers — the same `repository` object whose `owner.login` was used to pick the (possibly secret-less) app is not the object the handlers key their side effects on; they read `repository.full_name`/`repository.owner.login` again independently to find the tracked `Stack`/`Commit`: [5](#0-4) 

Nothing enforces that `repository.owner.login` (used to select the verifying secret) is consistent with `repository.full_name` (used by handlers to identify which real, tracked repository/stack to mutate). An attacker can therefore submit a payload where these two fields point at different organizations/repositories.

The equality that should hold but does not:
`organization whose webhook_secret authenticated the request == repository/organization that the dispatched handlers act upon`

### Impact Explanation
If any organization configured in the Shipit instance has no `webhook_secret` set (an explicitly supported/default state per `config/secrets.development.example.yml` and `docs/setup.md`), an attacker with no credentials at all can craft a payload whose `repository.owner.login`/`organization.login` names that secret-less org (causing `verify_webhook_signature` to return `true` unconditionally) while setting `repository.full_name` to a real, protected repository tracked by the instance. The full attacker-controlled body is then processed by handlers exactly as if it had been legitimately signed for that real repository — e.g. the `status` handler creates a `CommitStatus` for an arbitrary `sha`/`state`/`context` on a real commit, or the `push` handler enqueues a `GithubSyncJob` against a real stack using an attacker-chosen `after` sha/ref. Spoofed passing CI statuses or synced refs can influence downstream merge/deploy decisions Shipit makes for that stack, i.e. an unauthorized deploy/merge/rollback outcome — meeting the Critical impact bar.

### Likelihood Explanation
Exploitation requires zero credentials when the deployment has at least one configured GitHub organization without a `webhook_secret`. This is a supported and, per the example config, default state (`webhook_secret: # nil`), making it a realistic operational condition, especially for multi-org Shipit instances mid-setup or organizations that intentionally rely on OAuth only. For instances where every configured org has a secret set, the same root cause (verification target chosen from unauthenticated payload data, independent from the object handlers act on) still exists but requires the attacker to already know that org's secret, which is out of scope per the rules.

### Recommendation
Bind the value used to select the verifying `GitHubApp`/secret to the same value the handlers use to identify the target repository, and validate they match after signature verification succeeds. Do not allow signature verification to trivially pass when `webhook_secret` is unset for an organization that owns repositories tracked elsewhere in the payload — either require a secret whenever any tracked `Stack`/`Repository` exists for candidate organizations, or reject payloads where `repository.owner.login` and `repository.full_name`'s owner segment disagree, prior to dispatching to handlers.

### Proof of Concept
1. Configure (or note the existing default) a Shipit organization, `orgA`, with no `webhook_secret` set, alongside a separately tracked, real stack for `victim-org/victim-repo` that does have webhook protection intended.
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "organization": { "login": "orgA" },
  "repository": { "owner": { "login": "orgA" }, "full_name": "victim-org/victim-repo" },
  "sha": "<real commit sha of victim-org/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example"
}
```
3. `verify_signature` calls `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` with no HMAC check at all.
4. `create` dispatches the full payload to the `status` handler, which creates a `CommitStatus` record for the real commit in `victim-org/victim-repo`, as demonstrated by the existing test asserting status creation from payload fields: [6](#0-5) 
5. The attacker has forged a CI status on a protected repository without ever knowing that repository's own webhook secret.

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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
