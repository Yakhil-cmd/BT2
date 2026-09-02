### Title
Webhook signature verified against `repository.owner.login` while event handlers act on `repository.full_name` - cross-organization forged status/push events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to validate the HMAC signature using `repository.owner.login` (with a fallback to `organization.login`), but the event handlers that actually mutate state (`PushHandler`, `StatusHandler`, etc.) resolve the target `Repository`/`Stack` using the separate `repository.full_name` field from the same JSON body. Nothing ties these two fields together, so a signature valid for organization A does not guarantee the payload's `repository.full_name` also belongs to organization A.

### Finding Description
The webhook signature check is: [1](#0-0) 

which derives the verification key via: [2](#0-1) 

i.e. `repository.owner.login` (or `organization.login`) chooses which `GitHubApp` config (and thus which `webhook_secret`) is used to check `X-Hub-Signature`.

However, once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches to handlers such as `PushHandler` and `StatusHandler`. These resolve the actual target repository/stacks not from `repository.owner.login`, but from `repository.full_name`: [3](#0-2) 

`Repository.from_github_repo_name` splits this string on `/` to find the owner/name pair independently of the field used for signature verification: [4](#0-3) 

`PushHandler#process` then triggers a GitHub sync for every matching stack, and `StatusHandler#process` writes commit statuses: [5](#0-4) [6](#0-5) 

Because real GitHub webhooks always keep `repository.owner.login` consistent with `repository.full_name`'s owner segment, this split never causes issues in the trusted GitHub-originated flow. But the engine itself performs no cross-check between the two fields. An attacker who is able to produce a validly-signed payload for **any one** configured organization (for example an organization configured with no `webhook_secret`, which `verify_webhook_signature` explicitly treats as auto-verified — `return true unless webhook_secret`, or an org whose secret the attacker otherwise legitimately possesses) can set `repository.owner.login` to that organization while setting `repository.full_name` to an entirely different, unrelated tracked repository belonging to another organization on the same Shipit instance. The signature check passes (bound to the attacker's own org), but the handler acts on a repository the attacker was never authorized for.

This is exactly the "organization that authenticated versus the repository that is written" binding break called out in the rules: `repository.owner.login`/`organization.login` is the field the signature verification is bound to, while `repository.full_name` is the field the mutating logic is bound to, and the two are never checked for equality. [7](#0-6) 

### Impact Explanation
Using this mismatch, an attacker can forge `status` events (`StatusHandler`) to write arbitrary commit statuses on commits belonging to a different, victim organization's stack, and forge `push` events (`PushHandler`) to trigger `stack.sync_github` for a victim's stack. Given that `continuous_deployment` and CI-status-gated auto-deploys rely on commit statuses and sync state being trustworthy signals, this can be leveraged to manipulate the merge/deploy decision pipeline (fake "green" CI status, or trigger a resync at an attacker-chosen time) for a repository the attacker does not control — a cross-organization/cross-repository write achieved without holding that organization's `webhook_secret`, `ApiClient` token, or repository write access. This matches the "cross-repository writes" / "unauthorized deploy" impact class since injected/forged statuses feed directly into deploy-gating logic.

### Likelihood Explanation
Exploitability depends entirely on the operator's multi-org configuration: it requires either (a) an organization configured in `Shipit.github` with a blank/nil `webhook_secret` (shown as a valid, documented configuration shape in `config/secrets.development.shopify.yml` and `test/dummy/config/secrets.test.json`, both setting `webhook_secret: null`), which per `verify_webhook_signature` auto-passes verification for that org's namespace, or (b) an attacker who legitimately controls a webhook secret for one org onboarded to the same Shipit instance and wants to target a sibling org's stacks. Since Shipit is designed to host multiple organizations/repositories behind one webhook secret-set (`Shipit.github(organization:)`), this is a realistic deployment shape, but the practical likelihood is moderate — it needs a multi-tenant deployment with at least one under-configured org.

### Recommendation
After signature verification succeeds, re-derive `repository_owner` from the same field the handlers use (`repository.full_name`'s owner segment) and require it match the field used to select the verification secret, or simplify by verifying the signature using the secret keyed off `repository.full_name`'s owner instead of a separate look-up field. Additionally, treat an organization with a blank `webhook_secret` as unverifiable/rejected rather than auto-passing (`GitHubApp#verify_webhook_signature`'s `return true unless webhook_secret`), since that bypass is the easiest way to obtain a "validly signed" payload for injecting a mismatched `repository.full_name`.

### Proof of Concept
1. Configure (or find) an organization `org-a` in `Shipit.github` with `webhook_secret: null` (a supported configuration, as shown in `test/dummy/config/secrets.test.json`).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim commit sha in org-b/target-repo>",
  "state": "success",
  "context": "ci/tests",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/target-repo"
  }
}
```
3. `verify_signature` resolves `repository_owner` = `"org-a"`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of any/no `X-Hub-Signature` header.
4. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` (unrelated to `org-a`) and calls `create_status_from_github!`, writing a forged "success" status onto a commit belonging to `org-b/target-repo`, potentially satisfying that stack's CI-gating for auto-deploy — despite the attacker never possessing `org-b`'s webhook secret, API token, or repository access.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
