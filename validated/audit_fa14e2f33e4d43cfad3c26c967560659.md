### Title
Webhook signature verification is keyed off an attacker-controlled "owner" field that is never cross-checked against the repository the event actually writes to - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
The C4 finding is a rounding function that silently coerces a value that should reflect one thing (a 25%-OTM strike derived from the live price) into a different, unchecked value (a `roundingPrecision`-clamped price), breaking the "strike approved == strike executed" invariant. The structural analog in Shipit is that the field used to pick *which organization's secret verifies the signature* is not the same field, nor cryptographically bound to, the field used to decide *which repository/stack the event is applied to*. The HMAC only proves "this payload was sent by whoever holds the secret for the org named in the payload itself" — it never proves that the `repository.full_name` used later by the handlers belongs to that same, secret-holding org.

### Finding Description
`WebhooksController#verify_signature` derives the organization used to select `Shipit.github(organization:)` purely from the untrusted payload: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` only performs an HMAC comparison *if* a `webhook_secret` happens to be configured for that org; if not configured it unconditionally returns `true`: [3](#0-2) 

Configuration examples in this engine explicitly allow `webhook_secret` to be left blank per organization: [4](#0-3) 

Meanwhile, every downstream `Handler` (push, status, membership, etc.) resolves the actual `Stack`/`Repository` to mutate from a *separate* payload field, `repository.full_name`, which is not the field used for the org->secret lookup and is never re-validated against it: [5](#0-4) 

So the equality the design implicitly assumes is:
`org(secret used to verify signature) == owner(repository.full_name used to find the Stack acted on)`

This equality is not enforced anywhere. The signature check only proves the payload matches *some* org's secret (or no secret at all, if unconfigured); the `full_name` used to select the Stack is a free-form string inside the same unverified-until-the-fact JSON body, so once verification is satisfied for org A (e.g., because org A has no `webhook_secret` set — a supported, documented configuration), the payload's `repository.full_name` can name a Stack that belongs to a completely different, properly-secured org B.

`push_handler.rb` shows this dynamic concretely: it never checks that `payload['repository']['owner']['login']` (the org verify_signature authenticated) matches the owner portion of `repository_name` used by `stacks`: [6](#0-5) 

The `status` handler exhibits the same pattern — it writes a `Status` record from attacker-suppliable `sha`/`state`/`context`, gated only by the same organization-derived signature check, as exercised in the controller test: [7](#0-6) 

### Impact Explanation
Commit statuses (`state: success`, arbitrary `context`) are what Shipit's `ci.require` deploy-safety gate consults to decide whether a commit is "deployable." If an attacker can get a forged `status` webhook accepted under an org whose `webhook_secret` is unset (a valid, documented deployment configuration in this engine, not a host-mounting deviation), but target it — via the unchecked `repository.full_name` field — at a Stack belonging to a different, properly configured organization, they can mark an arbitrary commit as CI-passing. Combined with `continuous_deployment` on that Stack, this results in an **unauthorized deploy** of a commit that never actually passed CI, matching this engine's own Critical/High bar ("an unauthorized deploy" / "unauthenticated read of stack state ... or an unauthorized deploy"). This is a direct analog of the source bug: a value (`strike`) that is supposed to be tightly bound to a verified input (spot price) instead gets silently substituted by an unrelated, coarser value (`roundingPrecision`-clamped constant), invalidating the safety assumption built on top of it.

### Likelihood Explanation
Exploitability requires only: (1) the deploying organization runs Shipit with more than one GitHub App/org configured (a documented, supported multi-tenant setup, see `config/secrets.development.shopify.yml`), and (2) at least one configured org has no `webhook_secret` set — which the code explicitly tolerates rather than rejects (`return true unless webhook_secret`). No `ApiClient` token, `webhook_secret`, or repository write access is needed by the attacker; they only need to know a target Stack's `owner/repo` full name, which is public information for any public repository. This is a plausible, config-supported condition rather than a purely theoretical one, since the engine's own example secrets files ship with `webhook_secret: nil`.

### Recommendation
Bind the identity used for signature verification to the identity used for record lookup: derive the org used to select the `Stack`/`Repository` strictly from the same, already-authenticated `repository_owner`/organization value used in `verify_signature`, and reject (422) any event where `repository.full_name`'s owner does not match the org whose secret verified the signature. Additionally, stop treating a missing `webhook_secret` as an implicit "skip verification" — require an explicit `allow_unsigned: true` opt-in per org, and log/alert loudly when it is enabled, so blank-secret orgs cannot be used as a signature-bypass pivot to affect other orgs' stacks.

### Proof of Concept
1. Configure Shipit with two orgs: `secure-org` (has `webhook_secret` set) and `open-org` (no `webhook_secret`, e.g. as shown in `config/secrets.development.shopify.yml`).
2. `secure-org` has no meaningful relationship to `secure-org/target-repo`, a real Stack belonging to `secure-org` with `continuous_deployment: true` and `ci.require: ["ci/build"]`.
3. Attacker POSTs to `/github/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "open-org" }, "full_name": "secure-org/target-repo" },
  "sha": "<attacker-chosen-sha-on-target-repo>",
  "state": "success",
  "context": "ci/build",
  "description": "forged",
  "target_url": "https://example.com"
}
```
4. `verify_signature` resolves `repository_owner` to `open-org`; `Shipit.github(organization: 'open-org').verify_webhook_signature` returns `true` unconditionally because `open-org` has no `webhook_secret`, per `lib/shipit/github_app.rb:76-77`.
5. The status handler proceeds using `repository.full_name = "secure-org/target-repo"` (per `Handler#repository_name`, `app/models/shipit/webhooks/handlers/handler.rb:36-38`) and writes a passing `Status` for the attacker-chosen sha on `secure-org`'s stack, even though the signature never authenticated anything belonging to `secure-org`.
6. If continuous deployment is enabled on that stack, the next scheduling cycle deploys the now-"CI-green" attacker-chosen commit — an unauthorized deploy triggered without ever possessing `secure-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
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
