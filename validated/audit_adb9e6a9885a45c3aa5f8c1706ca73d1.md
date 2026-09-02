### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while event handlers act on `repository.full_name` — allows cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), but the actual event handlers that resolve which `Stack`/`Repository` to act on key off `repository.full_name`. Because the HMAC signature covers the entire raw JSON body, an attacker who legitimately controls one organization's GitHub App `webhook_secret` in a multi-org Shipit deployment can produce a validly-signed payload where `repository.owner.login` names their own org (to pass signature verification) while `repository.full_name` names a stack belonging to a different organization, causing Shipit to process a webhook "as if" it came from a repository it was never authorized for.

### Finding Description
`verify_signature` computes the verifying organization from the payload itself: [1](#0-0) [2](#0-1) 

The signature check itself is a plain HMAC over the full raw request body using that organization's configured `webhook_secret`: [3](#0-2) 

In a "Using Multiple GitHub Applications" deployment (documented for handling multiple orgs from one Shipit instance), each organization has its own `webhook_secret`, known to that organization's own admins/GitHub App owners: [4](#0-3) 

Once `head(422)` is *not* triggered, `create` hands the entire parsed `params` — including whichever `repository.full_name` the attacker chose — to the registered event handlers: [5](#0-4) 

The equality the engine implicitly assumes is:
```
organization that produced a validly-signed payload (repository.owner.login / organization.login)
    ==
repository/stack that the handlers subsequently act on (repository.full_name)
```
Nothing in `verify_signature` or `create` enforces that these two payload fields are consistent with each other, and both fields are attacker-controlled content inside the same signed body — the attacker only needs to know one org's `webhook_secret` to produce a validly signed body containing an arbitrary `full_name`.

This is corroborated by the test suite: handlers are shown resolving repositories purely from `repository.full_name`, independent of `repository.owner.login`: [6](#0-5) [7](#0-6) 

### Impact Explanation
An attacker who administers (or otherwise knows the `webhook_secret` of) one GitHub organization configured in a multi-org Shipit instance can forge webhook events (`push`, `status`, `check_suite`, `membership`, etc.) that are attributed to a different organization's repositories/stacks simply by setting `repository.full_name` to point at that other org's repo while keeping `repository.owner.login`/`organization.login` set to their own org. Depending on which handler is triggered, this can enqueue `GithubSyncJob`/`RefreshCheckRunsJob`, create commit `Status` rows, or otherwise manipulate CI/merge-queue state (`ci_missing`/`ci_failing` gating used by `MergeRequest#reject_unless_mergeable!`) for a stack the attacker does not control, potentially manufacturing a passing CI status that clears the way for an unauthorized merge/deploy on another organization's repository. This aligns with the "organization that authenticated versus the repository that is written" cross-repository trust-binding class called out in scope.

### Likelihood Explanation
This requires (a) a Shipit deployment configured with the multi-organization `github:` block documented in `docs/setup.md`, and (b) the attacker possessing a legitimate `webhook_secret` for at least one configured organization (which any admin of that org's GitHub App inherently has, without needing any Shipit credential, session, or repository write access to the *target* repository). No `ApiClient` token, session, or GitHub write access to the victim repo is required — only knowledge of one org's own webhook secret, which is a normal, unprivileged-with-respect-to-the-target credential.

### Recommendation
In `WebhooksController#verify_signature`/`create`, cross-check that `repository.full_name`'s owner segment matches the organization whose secret validated the signature (or, in single/known-org handlers, re-derive the organization strictly from `repository.full_name` rather than trusting a separate `owner.login`/`organization.login` field for secret selection). Reject payloads where these two fields diverge.

### Proof of Concept
1. Deploy Shipit with multi-org config: `github.orgA.webhook_secret = secretA`, `github.orgB.webhook_secret = secretB` (attacker only knows `secretA`, controls org A's GitHub App).
2. Attacker crafts JSON body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" },
  ...
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(secretA, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push` (or `status`).
4. `verify_signature` calls `Shipit.github(organization: 'orgA')`, which verifies successfully since the attacker used `secretA` correctly.
5. `create` dispatches `params` (with `full_name = "orgB/target-repo"`) to the `push`/`status` handler, which resolves and mutates state for `orgB`'s stack — despite the request never having been signed by `orgB`.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end
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
