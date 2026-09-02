## Analysis Result

I found a valid analog: the webhook signature verifier selects which GitHub organization's `webhook_secret` to check against using `repository.owner.login` (or `organization.login`), while every downstream event handler resolves the actual repository/stack to act on using the independent `repository.full_name` field from the same JSON body. These two fields are never cross-checked against each other, and per the documented, supported multi-org configuration (`docs/setup.md:182-209`, `config/secrets.development.shopify.yml`), `webhook_secret` is explicitly optional per-organization.

### Title
Webhook Signature Verification Bound to `repository.owner.login` While Event Processing Trusts the Unrelated `repository.full_name` Field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against based on `repository.owner.login` (falling back to `organization.login`) [1](#0-0) , then looks it up via `Shipit.github(organization: repository_owner)` [2](#0-1) . If that organization has no configured `webhook_secret` (a supported, documented setup — see `docs/setup.md:182-209` and `config/secrets.development.shopify.yml:1-23`), `GitHubApp#verify_webhook_signature` unconditionally returns `true` [3](#0-2) . Every webhook handler, however, resolves the actual repository/stack to act on from a completely different JSON field — `repository.full_name` — via `Handler#repository_name`/`#stacks` [4](#0-3) , used identically by `PushHandler` [5](#0-4)  and `StatusHandler` [6](#0-5) .

### Finding Description
The binding that should hold is: `organization whose secret validated the signature == organization owning the repository actually written to`. In practice the code breaks it: `repository_owner` (used only to select a secret) and `repository.full_name` (used to select the target) are independent, attacker-controlled strings inside the same unsigned-until-verified JSON body. An attacker who knows (or guesses/documented-default) that at least one configured GitHub organization on the instance has no `webhook_secret` set can craft a POST to `/webhooks` naming that org as `repository.owner.login`/`organization.login` (so `verify_webhook_signature` trivially passes with no valid signature at all) while setting `repository.full_name` to an entirely different, real, protected stack's repository. This is directly analogous to the reported `getFromCache` class of bug: a verification step is anchored on one identifier while the operation performed is against a different, unverified identifier extracted from the same object — exactly the "verified vs. actually used" mismatch called out in the report.

### Impact Explanation
Via `StatusHandler`, this allows an unauthenticated attacker to forge arbitrary commit statuses (`state`, `context`, `description`, `target_url`) for any commit SHA of any stack configured in the Shipit instance [7](#0-6) . Because `deploy_spec.required_statuses`/`ci.require`/`ci.blocking` gate whether a deploy is allowed [8](#0-7) , an attacker can mark blocking/required CI statuses as `success` for a commit that never actually passed CI, clearing the way for (or directly enabling continuous-delivery-triggered) an unauthorized deploy of unreviewed code — this matches the "unauthorized deploy" Critical impact category. Via `PushHandler`, an attacker can also force arbitrary `GithubSyncJob`s against any stack's repository [5](#0-4) , and via `pull_request` handlers can manipulate `ReviewStack` provisioning/archival for any repository.

### Likelihood Explanation
Requires no credentials, no session, no API token — only a raw POST to the public `/webhooks` endpoint (`skip_before_action :verify_authenticity_token`, no auth requirement) [9](#0-8) . The precondition (at least one configured organization without a `webhook_secret`) is explicitly presented as a normal, supported configuration in the project's own setup docs and example secrets files, not a misconfiguration outside the engine's control [10](#0-9) .

### Recommendation
Bind the two identifiers: derive the organization used for `Repository.from_github_repo_name`/stack lookup from the same, signature-covered `repository.owner.login` that was used to select the verifying secret (or reject any payload whose `repository.full_name` owner does not match `repository.owner.login`/`organization.login`). Alternatively, require every configured GitHub organization to have a non-blank `webhook_secret`, removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Given a multi-org Shipit instance where `OrgWithoutSecret` has `webhook_secret: nil` (per `docs/setup.md:182-209`) and a real stack exists for `victim-org/victim-repo`:
```
POST /webhooks
X-Github-Event: status

{
  "sha": "<sha of a real, currently-pending commit on victim-org/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "OrgWithoutSecret" }
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "OrgWithoutSecret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (absent/invalid) `X-Hub-Signature` header. `StatusHandler#process` then finds the real commit by `sha` and records the forged `success` status, independent of the org used for verification.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
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
