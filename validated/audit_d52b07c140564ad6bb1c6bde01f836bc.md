### Title
Cross-organization webhook forgery via GitHub-App key selection based on unverified payload field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects **which** configured GitHub App's `webhook_secret` to use for HMAC verification based on `repository_owner`, a value read straight out of the same untrusted JSON body that is later used by event handlers to pick the target repository/stack. In a multi-organization Shipit deployment (a supported, documented configuration), an attacker who only knows the webhook secret of *one* configured organization can forge a signed payload whose `repository.owner.login` matches that known org (so the signature check passes) while `repository.full_name` (used downstream to resolve the actual `Repository`/`Stack`) points at a different, victim organization's repository. This breaks the intended binding "the organization whose secret authenticated the request == the repository the handler writes to."

### Finding Description
`WebhooksController#verify_signature` derives the signing organization exclusively from the request body itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns a `GithubApp` instance configured with that organization's own `webhook_secret`, and `verify_webhook_signature` only checks that the HMAC over the raw body matches using that org's secret — it performs no additional check that the rest of the payload (e.g. `repository.full_name`) actually belongs to that same organization: [3](#0-2) 

Shipit explicitly supports hosting multiple GitHub organizations from one instance, each with an independent GitHub App/`webhook_secret`/`private_key`, as documented and fixtured: [4](#0-3) 

Once `verify_signature` passes, `create` hands the *entire unfiltered* parsed body to the registered handlers: [5](#0-4) 

Those handlers (push, status, check_suite, etc., under `app/models/shipit/webhooks/handlers/**`) resolve the target `Repository`/`Stack`/`Commit` using fields such as `repository.full_name`, independent of `repository.owner.login`. The controller test suite confirms handlers act on repository data taken from the same payload, keyed off `repository_params`/`full_name` rather than off whichever org's secret validated the signature: [6](#0-5) 

Because nothing ties `repository_owner` (used only to pick the verification key) to `repository.full_name` (used to pick the write target), a party who legitimately controls one org's webhook secret (e.g., they administer their own GitHub App/org that is one of several tenants on a shared Shipit instance) can set `repository.owner.login` to their own org (so the signature check succeeds against their own secret) while setting `repository.full_name` to `victim-org/victim-repo`. The equality the engine implicitly relies on — `signing_org(payload) == owning_org(target_repository)` — does not hold and is never enforced.

### Impact Explanation
This allows an attacker who is unprivileged with respect to a victim organization/repository hosted on the same shared Shipit instance to inject arbitrary, signature-"verified" webhook events that get applied to the victim's `Stack`/`Commit` records — e.g. forging a passing `status` event for a specific commit SHA in the victim repository. Commit statuses gate CI/deploy-readiness checks in Shipit (`ci.hide`, `allow_failures`, deployability), so this can be used to falsify CI state and enable an unauthorized deploy of a stack the attacker has no access to — a cross-repository write / unauthorized-deploy class of impact.

### Likelihood Explanation
Requires the Shipit instance to be configured with more than one GitHub organization (an explicitly documented, supported feature — not a misconfiguration), and requires the attacker to possess the `webhook_secret` of at least one of the configured orgs. This is realistic for shared/multi-tenant Shipit deployments where different, mutually untrusting orgs each register their own GitHub App against the same instance — each org's admins/CI systems legitimately have their own `webhook_secret` but should not be able to write into another org's stacks.

### Recommendation
Bind the organization used for signature verification to the organization actually targeted by the handler: after selecting the GitHub App by `repository_owner`, additionally verify that the resolved `Repository`'s owner matches `repository_owner` (or, better, verify against the specific repository/App installation the payload claims, not just the org-level secret) before dispatching to handlers. Reject events where `repository.full_name`'s owner segment does not match the org whose secret validated the signature.

### Proof of Concept
1. Configure a shared Shipit instance with two orgs, `attacker-org` and `victim-org`, each with its own GitHub App/`webhook_secret` (per `secrets_double_github_app.yml` layout).
2. As an account that only administers `attacker-org`'s GitHub App (no access to `victim-org`), craft a `status` webhook JSON body:
```json
{
  "sha": "<victim-repo commit sha>",
  "state": "success",
  "context": "ci/tests",
  "branches": [{"name": "master"}],
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": {"login": "attacker-org"}
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac(attacker-org webhook_secret, body)>` and `POST /webhooks` with header `X-Github-Event: status`.
4. `verify_signature` computes `repository_owner == "attacker-org"`, loads `attacker-org`'s `GithubApp`, and the HMAC matches — request passes with `head(:ok)` never triggered and no 422.
5. The status handler processes the body using `repository.full_name = "victim-org/victim-repo"`, creating/updating a `Status` on the victim's commit despite the attacker having no credentials for `victim-org`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-47)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
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
