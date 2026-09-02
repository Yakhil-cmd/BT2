### Title
Webhook signature is authenticated against `repository.owner.login`, but the stack that is mutated is resolved from the unauthenticated `repository.full_name` field of the same payload - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification from `params.dig('repository', 'owner', 'login')` [1](#0-0) , but `Shipit::Webhooks::Handlers::Handler` resolves the actual repository/stack to mutate from a *different* field of the same raw, attacker-supplied JSON body: `payload.dig('repository', 'full_name')` [2](#0-1) . These two fields are never bound to each other by the signature check — the HMAC only proves the request bytes were signed by *some* secret associated with whatever `repository.owner.login` says, not that `repository.full_name` matches that owner.

### Finding Description
Signature verification flow:
1. `verify_signature` computes `repository_owner` from the payload and looks up `Shipit.github(organization: repository_owner)`, then verifies `X-Hub-Signature` against `request.raw_post` using that organization's `webhook_secret` [3](#0-2) .
2. `GitHubApp#verify_webhook_signature` performs the HMAC-SHA1 comparison, but if no `webhook_secret` is configured for the selected organization, it returns `true` unconditionally [4](#0-3) .
3. Once the signature check passes, `create` dispatches the parsed JSON to the relevant `Shipit::Webhooks::Handlers::Handler` subclass (e.g. `PushHandler`) [5](#0-4) .
4. The handler resolves the target `Stack`/`Repository` using `payload.dig('repository', 'full_name')`, completely independent of `repository.owner.login` used earlier [2](#0-1) . `PushHandler` then syncs the resolved stack's branch to `params.after` [6](#0-5) .

Because `repository.owner.login` (authenticated org) and `repository.full_name` (repo actually written to) are independent, attacker-controlled strings inside the same signed byte blob, the HMAC check does not bind them together. Any principal who can produce a validly-signed payload for **one** organization configured in this Shipit instance (e.g. because that org has no `webhook_secret` configured — a legitimate, common configuration per `github_app_config` [7](#0-6)  — or because that org's secret leaked) can set `repository.owner.login` to that organization while setting `repository.full_name` to an unrelated victim repository hosted under a **different** organization also served by the same Shipit instance. The request passes `verify_signature` (verified against the low-security/no-secret org) and then `Repository.from_github_repo_name` happily resolves and mutates the victim stack based on `full_name` [8](#0-7) .

This is the structural analog of the reported bug class: a value that is checked/authorized (`repository.owner.login` against a specific org's trust boundary) is not the same value that is subsequently acted upon (`repository.full_name`, which drives stack mutation), and no cryptographic binding ties the two together — mirroring the "organization authenticated versus repository written" trust-binding break called out in the task rules.

### Impact Explanation
Exploiting this lets an attacker who controls (or knows the secret/no-secret status of) any single organization mounted on the Shipit instance forge webhook events — `push` (triggers `GithubSyncJob`/branch head updates) [6](#0-5) , `status`/`check_suite` (affects deployability gating), and `pull_request` events (auto-provisioning/archiving review stacks) — against a stack belonging to a completely different, unrelated organization/repository configured in the same multi-tenant Shipit deployment. This can desynchronize deployable state, force unwanted syncs, or manipulate review-stack provisioning/archival for a repo the attacker does not control, i.e. cross-repository writes without possessing that repository's actual webhook secret.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`github_organizations`/`github_app_config`) where at least one configured organization has no `webhook_secret` set, or where the attacker otherwise controls one org's secret while a victim org/repo exists on the same instance. This is a plausible, documented configuration path (`webhook_secret` is optional per the `verify_webhook_signature` short-circuit) rather than a purely theoretical setup, but it does require multi-tenant hosting of unrelated repositories on one Shipit instance.

### Recommendation
Bind the two fields together during verification: after selecting the GitHub App by `repository.owner.login`, verify that `repository.full_name`'s owner segment matches `repository.owner.login` before dispatching to handlers, or better, have `Handler#repository_name` cross-check against the organization already authenticated in the controller instead of trusting an independent payload field. Alternatively, require `webhook_secret` to be present for every configured organization so the "return true unless webhook_secret" bypass in `GitHubApp#verify_webhook_signature` cannot be used as the low-security foothold.

### Proof of Concept
1. Deploy Shipit with two organizations in secrets: `org-a` (no `webhook_secret` configured) and `org-b` (hosts victim repo `org-b/victim-repo`, with a stack tracked in Shipit).
2. Send a `push` webhook: headers `X-Github-Event: push`, `X-Hub-Signature: sha1=anything` (or omitted); body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "org-a")`; since `org-a` has no `webhook_secret`, `verify_webhook_signature` returns `true` regardless of the signature header [9](#0-8) .
4. `PushHandler` resolves stacks via `repository.full_name = "org-b/victim-repo"` [2](#0-1)  and enqueues `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack [6](#0-5) , despite the attacker never possessing `org-b`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
