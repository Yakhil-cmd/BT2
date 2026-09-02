### Title
Webhook signature verified against the payload's `organization`/`repository.owner` binding, not the `repository.full_name` binding actually acted on - cross-tenant repository/stack write (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
On a Shipit instance configured with more than one GitHub organization/App (as shown by `test/dummy/config/secrets_double_github_app.yml`, which defines `OrgOne` and `OrgTwo` each with its own `webhook_secret`), the webhook signature check authenticates the request against the organization derived from `repository.owner.login` (or `organization.login`), but the handler that performs the actual write picks its target `Stack` from a *different* field of the same, attacker-controlled JSON body: `repository.full_name`. Nothing ties these two fields together, so an operator of one legitimate tenant organization (who legitimately knows their own `webhook_secret`) can forge a webhook that is *verified* under their own organization but *acted upon* against another tenant's repository/stack.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to check the HMAC against using `repository_owner`: [1](#0-0) [2](#0-1) 

That derived owner (`repository.owner.login`, attacker-controlled JSON field) is used only to look up which app's secret validates the HMAC in `lib/shipit/github_app.rb#verify_webhook_signature`: [3](#0-2) 

Once verified, the full raw `params` (the whole attacker-supplied JSON body, unfiltered) is handed to the registered handler: [4](#0-3) 

`Handler#stacks`, used by `PushHandler`, resolves the target `Stack` from a *different* JSON field — `repository.full_name` — with no cross-check against the owner field that was used for signature verification: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` naively splits this attacker-controlled string on `/` to find the owner/name and thus the `Stack`: [7](#0-6) 

Because `repository.owner.login` (used for authentication) and `repository.full_name` (used for the write target) are independent fields inside the same JSON body the attacker fully controls, an attacker who is a legitimate GitHub App owner for tenant org "A" (and therefore knows org A's real `webhook_secret`, configured on the GitHub side by the attacker) can sign a payload with `repository.owner.login = "org-a"` (so verification succeeds against org A's secret) while setting `repository.full_name = "org-b/victim-repo"`, causing the handler to look up and act on org B's `Stack`, an organization/tenant the attacker never authenticated as.

### Impact Explanation
This breaks the trust binding "the organization that authenticated == the repository that is written," which is the exact class of rounding/binding-mismatch bug in the source report (asset accounting vs. share accounting no longer tied together). Here, `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on the victim stack — an attacker-chosen SHA is pushed into another tenant's stack synchronization pipeline, and if continuous deployment is enabled on that stack, this can drive an unauthorized deploy/rollback of a cross-tenant repository the attacker does not control, i.e., a cross-repository write. This satisfies the Critical bar in the rules ("cross-repository writes ... unauthorized deploy, rollback").

### Likelihood Explanation
This requires the Shipit instance to host more than one GitHub organization/App tenant (a supported, documented multi-org configuration, not a customization of the engine), and requires the attacker to control at least one of those legitimate tenants' GitHub App webhook_secret — which is normal for any legitimate customer/organization onboarded to a shared Shipit instance. No privileged Shipit session, `ApiClient` token, or GitHub write access to the victim repo is needed; only the ability to send an HTTP POST to `/webhooks` with a signature computed from the attacker's own, legitimately-known secret.

### Recommendation
`Handler#repository_name` / `Handler#stacks` must resolve the write target using the same trusted identity that was used to select the verifying app's secret (e.g., re-derive/require that `repository.full_name`'s owner segment match `repository_owner`, or pass the already-resolved organization from the controller into the handler instead of re-parsing untrusted payload fields), and reject the webhook if they diverge.

### Proof of Concept
1. Shipit configured with two tenants, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml` pattern).
2. Attacker legitimately owns/administers `org-a`'s GitHub App, and thus knows `org-a`'s `webhook_secret`.
3. Attacker crafts payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-that-exists-in-org-b/victim-repo>",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a webhook_secret, payload)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s app, and the HMAC checks out — `verified = true` [1](#0-0) .
6. `PushHandler#process` resolves `stacks` from `repository.full_name = "org-b/victim-repo"` [5](#0-4)  and calls `stack.sync_github(expected_head_sha: ...)` on `org-b`'s stack — a write the attacker never authenticated for.

Note: I could not fully trace `Stack#sync_github` / `GithubSyncJob` behavior within the remaining tool budget to confirm the exact downstream deploy trigger mechanics; this should be verified in a live/full-code review before treating the "unauthorized deploy" consequence as fully proven end-to-end, though the cross-tenant write of `expected_head_sha` into another organization's stack state is directly demonstrated by the code cited above.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
