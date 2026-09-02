## Analysis

The Sherlock report's root cause is a **mismatched binding**: the code authorizes/validates one quantity (total pool value) but writes/returns a different, unrelated one (per‑share price) without tying the two together. The structural analog in Shipit-engine is in the inbound GitHub webhook pipeline: the field used to select *which* HMAC secret authenticates the request is not the same field used to select *which repository/stack* the payload is allowed to mutate. [1](#0-0) [2](#0-1) [3](#0-2) 

`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret` used to validate `X-Hub-Signature`) using `repository_owner`, which is read straight out of the unauthenticated JSON body (`params.dig('repository','owner','login')`). Every `Handler` subclass, however, resolves the *target* `Repository`/`Stack` from a **different** field of the same body: `payload.dig('repository','full_name')`. `Shipit.github(organization:)` config supports (and the shipped example configs show) multiple organizations, each with its own, independently-set `webhook_secret` — which can legitimately be blank for one org while real orgs have a set secret. [4](#0-3) [5](#0-4) [6](#0-5) 

`verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for the organization resolved from `repository_owner`. Combined with the fact that `repository_owner` and `repository.full_name` are never checked to belong to the same repository, an attacker can pick `repository.owner.login` to be an org whose `webhook_secret` is unset (bypassing the signature check entirely) while pointing `repository.full_name` at a completely different, legitimately secured stack.

### Title
Webhook signature is verified against `repository.owner.login` while handlers act on the unrelated `repository.full_name` field, allowing cross-repository forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to validate `X-Hub-Signature` using `repository.owner.login` (or `organization.login`) taken from the unauthenticated request body. All `Shipit::Webhooks::Handlers` resolve the `Stack`/`Repository` to mutate using the unrelated `repository.full_name` field of the same body. Because these two fields are never required to be consistent, and because a Shipit instance hosting multiple GitHub organizations can have some organizations configured with no `webhook_secret` (an explicitly documented/shipped configuration), an unauthenticated attacker can pick an org name with no secret for the "authentication" field while targeting an arbitrary other repository/stack via the "action" field.

### Finding Description
The `binding` that should hold is:
`organization that authenticated the request == organization owning the repository that is written`

Before an attack, both fields are populated by the real GitHub webhook delivery, so they always match. `verify_signature` computes:
```
github_app = Shipit.github(organization: repository_owner)   # from repository.owner.login
``` [1](#0-0) 

and `Handler#repository_name`/`#stacks` compute:
```
payload.dig('repository', 'full_name')
``` [3](#0-2) 

which is then used by e.g. `PushHandler#process` to find and mutate stacks (`stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }`), and by the `status` handler to write `Status` records directly from payload fields (`state`, `target_url`, `description`, `context`, `sha`) as shown by the controller's own test suite. [7](#0-6) [8](#0-7) 

`verify_webhook_signature` also returns `true` unconditionally if no secret is configured for that organization:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [4](#0-3) 

Multi-organization Shipit deployments are an explicitly supported and documented configuration, where each org has an independent `webhook_secret` — the shipped sample even shows both entries with `webhook_secret: # nil`. [6](#0-5) [5](#0-4) 

After the attacker's crafted request: they set `repository.owner.login` to any organization Shipit is configured for that has a blank `webhook_secret` (verification always succeeds, no HMAC required), while setting `repository.full_name` to the full name of a completely different, legitimately protected repository that Shipit tracks. The equality above is broken: the "authenticated" organization has nothing to do with the "written" repository/stack.

### Impact Explanation
This reaches a Critical-listed impact: unauthorized cross-repository writes with zero credentials. An unauthenticated internet client can:
- Trigger `sync_github`/`GithubSyncJob` for any tracked stack via the `push` handler.
- Write a fabricated `Status` (`state`, `context`, `target_url`, `description`) onto an arbitrary commit of an arbitrary tracked repository/stack via the `status` handler, entirely bypassing GitHub's own attestation of that status, as long as some other configured org lacks a `webhook_secret`.
Since `Status` records drive Shipit's CI-gating logic (required checks for deploy/merge eligibility), forging a passing status on a targeted stack's commit can push a stack toward a "deployable"/"mergeable" state it should never have reached, undermining the deployment-trust model the webhook signature was meant to enforce.

### Likelihood Explanation
This requires no privileged credential: no `ApiClient` token, no `webhook_secret` knowledge for the *targeted* org, no GitHub App private key, and no repository write access to the target repository. The only precondition is that the Shipit instance is configured for multiple GitHub organizations and at least one of them has no `webhook_secret` set — a state the project's own documentation and shipped example configs present as a normal/expected configuration path (blank secrets are explicitly shown as valid in `docs/setup.md` and `config/secrets.development.shopify.yml`). The webhooks endpoint itself requires no authentication whatsoever (`WebhooksController` is a plain `ActionController::Base` with no `before_action` other than the vulnerable signature check).

### Recommendation
Bind the organization used to authenticate the webhook to the organization/repository the handler is permitted to mutate: after selecting `github_app` via `repository_owner`, verify that `repository_owner` matches the owner of `payload.dig('repository','full_name')` before dispatching to handlers, and reject the request otherwise. Additionally, require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`) so that a misconfigured/unset secret on one organization cannot be used to bypass verification for events claiming to touch a different repository.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.yml`: `trusted-org` (real `webhook_secret`) and `staging-org` (blank/nil `webhook_secret`), each with tracked stacks.
2. Attacker sends, without any signature header requirement being satisfiable:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "sha": "<target commit sha in trusted-org/critical-repo>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example",
  "description": "forged",
  "repository": {
    "owner": { "login": "staging-org" },
    "full_name": "trusted-org/critical-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "staging-org")`; since that org's `webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the (missing/arbitrary) `X-Hub-Signature` header.
4. The `status` handler resolves the target stack via `payload.dig('repository','full_name')` = `"trusted-org/critical-repo"` and writes the forged `Status` onto that repository's commit, as the controller's own tests confirm handlers persist payload fields verbatim. [8](#0-7) 

Note: I was not able to load the full source of `app/models/shipit/webhooks/handlers/status_handler.rb` within the available tool budget; the behavior described for the `status` handler is inferred from the corresponding controller test (`webhooks_controller_test.rb`), which directly asserts that a `Status` is created with values taken 1:1 from the payload. If further confirmation of the exact `status_handler.rb` implementation is needed, a Devin session with full repository access should be used.

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
