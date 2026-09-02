### Title
Unauthenticated Webhook Forgery via Optional `webhook_secret` and Attacker-Controlled Organization Selection - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App configuration (and therefore which `webhook_secret`) to validate an inbound webhook against, using a value taken from the **unauthenticated payload itself** (`repository.owner.login` / `organization.login`). If the organization resolved this way has no `webhook_secret` configured — which the setup documentation explicitly describes as optional — signature verification is unconditionally bypassed, and the same untrusted payload is then used by the webhook handlers to select the `Stack`, `Repository`, `Commit`, `Team`, or `Membership` records to mutate.

### Finding Description
`verify_signature` derives the organization used for verification purely from the request body: [1](#0-0) [2](#0-1) 

The resolved app's `verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is blank: [3](#0-2) 

`webhook_secret` is treated throughout the codebase and docs as optional, including in the official setup guide ("Webhook secret (optional)") and in every example secrets file (`webhook_secret: # nil`): [4](#0-3) [5](#0-4) 

Once `head(422) unless verified` is skipped (because `verified` is `true`), `create` dispatches the raw, attacker-supplied JSON to every registered handler for the claimed `X-Github-Event`: [6](#0-5) 

Those handlers then act on other fields of the same unverified payload — e.g. `push` enqueues a `GithubSyncJob` keyed off `repository.full_name`, `status` creates a `Status` on an arbitrary commit, and `membership` creates/removes `Team`/`Membership`/`User` records — as shown by the existing test suite exercising these code paths: [7](#0-6) [8](#0-7) [9](#0-8) 

The equality that should hold is: **organization whose signature was verified == organization that owns the repository/records mutated by the payload**. Because the verification key is chosen from the same untrusted field it is meant to protect, and because a blank `webhook_secret` (a documented, common configuration) makes verification a no-op, this equality can be trivially broken by an unauthenticated third party who simply knows/guesses a configured organization name that has no secret set.

### Impact Explanation
This is a direct authentication bypass on the primary unauthenticated ingress endpoint of the engine (`POST /webhooks`, `skip_before_action :verify_authenticity_token`). An attacker who identifies any configured GitHub organization without a `webhook_secret` can forge arbitrary GitHub events for repositories under that organization:
- Forge `push` events to trigger `GithubSyncJob` against arbitrary branches/commits.
- Forge `status`/`check_suite` events to fake CI green checks, potentially unlocking deploys gated on CI status.
- Forge `membership` events to add/remove `Team` and `Membership`/`User` records, escalating into `Shipit.github_teams` authorization.
- Forge `pull_request` events handled by review-stack/merge-queue adapters.

These map onto the in-scope Critical/High impacts: authentication bypass and escalation into `Shipit.github_teams` authorization / unauthorized state changes that gate deploys.

### Likelihood Explanation
Likelihood is high in any deployment that follows the documented setup without setting a webhook secret (explicitly called "optional" in `docs/setup.md`), or for any additional organization added later in a multi-org config where the secret field is left blank (the example templates default it to `nil`). No credentials, GitHub App keys, or Shipit sessions are required — only knowledge of a configured organization/repository name, which is often public.

### Recommendation
- Do not let attacker-supplied payload fields determine the verification key; resolve the organization from a value the operator controls out-of-band (e.g., per-route or per-installation ID validated against a trusted GitHub App attribute), not from `repository.owner.login`/`organization.login` in the raw body.
- Make `webhook_secret` mandatory (fail closed) rather than treating its absence as "signature verified."
- After signature verification, additionally verify that the resolved organization matches the organization actually referenced by the payload fields consumed by each handler (repository/stack ownership check) before persisting any state.

### Proof of Concept
1. Operator configures multiple GitHub organizations per `docs/setup.md`'s multi-org schema; `OrgB` is configured but its `webhook_secret` is left blank (as shown in every shipped example/template).
2. Attacker (no Shipit credentials, no GitHub App key) sends `POST /webhooks` with `X-Github-Event: push` and a JSON body where `repository.owner.login == "OrgB"` and `repository.full_name` points at a real Stack's repository, with no valid `X-Hub-Signature` (or any arbitrary value).
3. `verify_signature` resolves `Shipit.github(organization: "OrgB")`; `verify_webhook_signature` returns `true` immediately because `OrgB`'s `webhook_secret` is blank [10](#0-9) .
4. `create` proceeds to run the `push` handler on the forged payload, enqueuing `GithubSyncJob` for the targeted stack, as verified by the existing (legitimate) test demonstrating this dispatch path [7](#0-6) , but here triggered without any valid signature at all.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
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
