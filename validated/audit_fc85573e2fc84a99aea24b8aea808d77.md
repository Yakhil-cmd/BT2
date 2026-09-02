### Title
Cross-organization webhook forgery — signature verified against `repository.owner.login`, but target stack resolved from unrelated `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The webhook signature check authenticates the payload against the GitHub App/organization identified by `repository.owner.login` (or `organization.login`), while the code that determines *which* stack/repository actually gets mutated resolves the target purely from `repository.full_name`. Because these two fields are never cross-checked, a payload signed (or trivially accepted) for one organization can direct writes at a completely different, unrelated repository/stack.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to validate the HMAC signature using `repository_owner`, which is read from the payload itself: [1](#0-0) [2](#0-1) 

This binds the request's authenticity to whichever organization's `webhook_secret` is configured under `repository.owner.login`. Critically, `GithubApp#verify_webhook_signature` returns `true` unconditionally when that organization has no `webhook_secret` configured: [3](#0-2) 

Meanwhile, the actual event handlers never reference `repository.owner.login` at all. They resolve the target stack solely from `repository.full_name`: [4](#0-3) 

and act on it, e.g. `PushHandler` enqueues a sync for any stack matching the branch, using an attacker-supplied `after` SHA: [5](#0-4) 

This is the same class of bug as the external report: a value that is authenticated/verified (the organization owning the secret used for HMAC) is not the same value that is subsequently acted upon (the `full_name` used to select the mutated resource). The binding "organization that authenticated == repository that is written" is broken: `repository.owner.login` and `repository.full_name`'s owner segment are never compared anywhere in the controller or in `Handler#repository_name`/`#stacks`.

### Impact Explanation
An attacker who can get a payload accepted for *any* configured (or misconfigured/secret-less) organization can set `repository.full_name` to point at an arbitrary, unrelated, higher-trust organization's repository/stack. Every webhook handler resolves its target exclusively via `full_name`, so this lets the attacker:
- Enqueue `GithubSyncJob` for a victim stack with an attacker-chosen `expected_head_sha` via `PushHandler`.
- Similarly forge other events (status, membership, pull_request, etc.) against a victim's stack, since all handlers share the same `Handler#stacks`/`#repository_name` resolution.

Because the fields backing "who signed this" and "what does this event modify" are decoupled, this is a cross-organization write that breaks the deployment-trust boundary between organizations configured in the same Shipit instance, matching the report's core defect pattern (checked value ≠ acted-upon value).

### Likelihood Explanation
Exploitability depends on the attacker being able to get *any* org's signature check to pass — either by knowing/controlling a low-trust organization's `webhook_secret` (an org they legitimately administer on the same Shipit instance) or by targeting an organization entry whose `webhook_secret` is left blank (explicitly supported and demonstrated as a valid configuration by `return true unless webhook_secret` and the shipped example config). Given multi-tenant Shipit deployments commonly host several organizations/apps with independently managed secrets, this is a realistic misconfiguration/low-privilege-abuse scenario rather than a theoretical one.

### Recommendation
In `Handler#repository_name`/`#stacks`, verify that the repository's owner (`repository.owner.login`) matches the organization whose secret was used to authenticate the request (the `repository_owner` computed in `WebhooksController#verify_signature`), and reject the event otherwise. Do not allow an organization's configured webhook secret to authorize events for repositories outside that organization.

### Proof of Concept
1. Attacker administers (or knows the `webhook_secret`, or exploits a blank `webhook_secret`) for organization `attacker-org`, which is configured in this Shipit instance alongside a higher-trust `victim-org`.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
3. `verify_signature` computes `repository_owner` = `"attacker-org"` and validates/accepts the signature using `attacker-org`'s (weak/blank/known) secret — see `app/controllers/shipit/webhooks_controller.rb:24-30,59-62` and `lib/shipit/github_app.rb:76-83`.
4. `PushHandler#process` resolves `repository_name` from `payload.dig('repository','full_name')` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), finds `victim-org`'s stacks, and calls `stack.sync_github(expected_head_sha: params.after)` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — mutating a stack that has no relationship to the credential that authenticated the request.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
