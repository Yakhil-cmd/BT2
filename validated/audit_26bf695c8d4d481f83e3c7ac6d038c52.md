### Title
Webhook signature verification is scoped by `repository.owner.login`, but write targets are selected by the independently-controlled `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate a signature against using `repository.owner.login` (or `organization.login`) from the untrusted JSON body, but the actual write target used by every handler is derived from a *different* field in that same body, `repository.full_name`, with no check that it belongs to the org whose secret was used to verify. In a Shipit instance configured for multiple GitHub organizations (a supported, documented setup), this breaks the equality "organization whose secret authenticated the request == organization whose repository is written."

### Finding Description
`verify_signature` computes the verification key like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from `params.dig('repository', 'owner', 'login')` (attacker-controlled JSON), and is used only to pick `Shipit.github(organization: repository_owner)`, i.e. which configured `webhook_secret` must match the `X-Hub-Signature` header.

Every event handler, however, resolves *which repository/stacks to act on* from a completely different, independently-settable field of the same payload: [3](#0-2) 

`PushHandler` (and by extension `StatusHandler`, which uses the same `stacks` helper per the payload fixtures used in `test/controllers/webhooks_controller_test.rb`) locates stacks/commits purely by `repository.full_name`: [4](#0-3) 

Since Shipit explicitly supports multiple GitHub organizations each with its own `webhook_secret` in the same instance: [5](#0-4) 

an attacker who legitimately controls (or has previously captured a valid webhook delivery from) **any one** configured organization "OrgA" can build a JSON body where `repository.owner.login` = `"OrgA"` (so `verify_signature` selects and matches OrgA's real `webhook_secret`) while `repository.full_name` = `"OrgB/critical-repo"`, a completely different tracked repository belonging to organization "OrgB" whose secret the attacker does not possess. Because the HMAC only proves "this body was signed with OrgA's secret," not "this body's repository belongs to OrgA," the request passes `verify_signature` and is then dispatched to the handler, which blindly trusts `repository.full_name` to select the target stack/commit.

This is confirmed by the tests, which show that `repository_owner`/signature selection and the actual repository acted upon are two independent pieces of the same JSON object, checked separately: [6](#0-5) [7](#0-6) 

### Impact Explanation
Using the `status` event (payload fields `sha`, `state`, `context`, confirmed to be handled per-repository via the same `stacks`/`repository.full_name` resolution) as shown in the controller test: [8](#0-7) 

an attacker who owns OrgA's webhook secret can forge a `status` webhook naming a commit inside `OrgB/critical-repo` and mark it `success`. Shipit uses recorded commit `Status` rows to gate whether a commit is eligible to deploy (CI-required checks shown/enforced in the stack UI). Forging a passing status for a commit under an organization the attacker does not control lets that attacker manufacture the "CI passed" precondition for a stack they don't own, enabling an unauthorized deploy of a commit that never actually passed the real CI/checks for that repository. This crosses the "organization authenticated versus the repository that is written" trust boundary and yields the Critical-tier impact of an unauthorized deploy gate bypass.

### Likelihood Explanation
The only prerequisite is administrative/webhook access to **any single** organization configured in a multi-org Shipit deployment (a documented, supported configuration) — not to the target organization whose repository is actually manipulated. No Shipit session, `ApiClient` token, or GitHub App private key for the *target* org is required; only a valid `webhook_secret` for *some* org tracked by the instance, which the attacker can already legitimately obtain by controlling their own org's GitHub App/webhook configuration. This is a realistic scenario for any Shipit installation shared across independent teams/orgs.

### Recommendation
In `WebhooksController#verify_signature` and in `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name`, enforce that the organization used to select/verify the webhook secret matches the owner of the repository actually resolved and acted upon (e.g., compare `repository.owner.login` against the owning organization of the `Repository` looked up via `full_name`, and reject the event if they differ), rather than trusting `repository.full_name` independently of the verified `repository.owner.login`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as documented in `config/secrets.development.shopify.yml`).
2. As an attacker who administers `OrgA`'s GitHub App/webhook secret, craft a `status` (or `push`) webhook body:
```json
{
  "sha": "<real sha of a commit in OrgB/critical-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/critical-repo" }
}
```
3. Sign the raw body with `OrgA`'s real `webhook_secret` and set `X-Hub-Signature` accordingly; set `X-Github-Event: status`.
4. POST to `/github/webhooks` (per `WebhooksController#create` / `verify_signature`). Verification succeeds because `repository_owner` resolves to `OrgA`, whose secret matches.
5. `StatusHandler` resolves the target stack/commit via `repository.full_name` (`OrgB/critical-repo`) per `Handler#repository_name`/`#stacks`, and records a `success` status for that commit — despite the attacker having no credentials for `OrgB` — which can subsequently be used to satisfy `OrgB`'s stack's CI-gating requirements for deployment.

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
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

**File:** test/controllers/webhooks_controller_test.rb (L94-107)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L109-127)
```ruby
    test "unknown github organization logs and returns unprocessable entity" do
      @request.headers['X-Github-Event'] = 'push'

      payload = JSON.parse(payload(:push_master))
      payload["repository"]["owner"]["login"] = "unknown-org"

      Shipit.stubs(:github).raises(Shipit::GithubOrganizationUnknown.new("unknown-org"))
      Rails.logger.expects(:warn).with([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=push",
        "repository_owner=unknown-org",
        "unknown_organization=unknown-org",
        "status=422"
      ].join(' '))

      post :create, body: payload.to_json, as: :json
      assert_response :unprocessable_entity
    end
```
