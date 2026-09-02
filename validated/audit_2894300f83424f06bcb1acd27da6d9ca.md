### Title
Webhook signature verification authenticates the *organization* but handlers act on an attacker-controlled *repository* field from the same unverified-for-consistency payload, enabling cross-repository/cross-stack forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to check *only* by the organization/repository-owner login found in the attacker-supplied JSON body, and then every event handler independently re-reads a different field of that same body (`repository.full_name`, or for `status` events nothing at all) to decide which `Stack`/`Commit` to mutate. Nothing binds "the org whose secret validated this request" to "the repository the handler ultimately writes to." An org/tenant that is legitimately onboarded to a shared Shipit instance (and therefore knows its own webhook secret) can sign a payload with its own org login but point `repository.full_name` (or, for status events, just a `sha`) at a victim stack it does not own, causing Shipit to sync arbitrary commits or forge commit statuses across repositories it has no authorization for.

### Finding Description
The binding that should hold is:
`organization authenticated by verify_webhook_signature == repository/stack actually written by the handler`

`verify_signature` selects the `GithubApp` (and thus the secret) using a field taken straight from the untrusted JSON body: [1](#0-0) [2](#0-1) 

The HMAC only proves "this body was signed with the secret configured for the org named in `repository.owner.login` (or `organization.login`)" — it says nothing about which repository the *content* of the payload targets. `Handler#stacks`/`#repository_name`, used by `PushHandler` and `CheckSuiteHandler`, independently re-reads `repository.full_name` from the same body to select which `Stack`s get mutated, with no cross-check that this repository belongs to the org that produced a valid signature: [3](#0-2) [4](#0-3) [5](#0-4) 

`StatusHandler` is worse: it performs no repository scoping whatsoever and matches purely on `sha` across the entire instance: [6](#0-5) 

This is the same class of bug as the reported `_solverFulfilled` issue: a trust decision (`fulfilled`/"signature verified") is made against one piece of state (`deposits`/`claims` at reconcile time, here "the org field"), while a *different* mutable piece of the same message (`_borrow()`/`_contribute()` afterwards, here "the repository field") is what is actually acted upon later, with no re-validation that the two agree.

### Impact Explanation
Any organization/tenant configured in a multi-tenant Shipit deployment (i.e., any party that legitimately knows its own configured webhook secret) can forge webhook deliveries that are accepted as authentic by `verify_signature`, then use the `repository.full_name` (push/check_suite) or bare `sha` (status) fields to act on a completely different, victim repository's stacks and commits. This allows:
- Forcing `Stack#sync_github` on a victim stack with an attacker-chosen `expected_head_sha` via `PushHandler`, and
- Forging commit statuses (`create_status_from_github!`) on arbitrary commits instance-wide via `StatusHandler`, which can flip a commit from red to green and unblock deploys/merges that depend on required checks.

This is a cross-repository write / integrity break driven by a forged-but-technically-"authenticated" webhook, matching the in-scope "escalation into authorization" / "cross-repository writes" impact class.

### Likelihood Explanation
Requires the attacker to control at least one organization/repository that is already onboarded to the shared Shipit instance (so they know their own configured webhook secret) — this is an unprivileged-attacker analog only in a multi-tenant deployment where multiple orgs share one Shipit instance with distinct per-org secrets, consistent with the `Shipit.github(organization:)` / `GithubOrganizationUnknown` per-org lookup pattern in `lib/shipit/github_app.rb` and `webhooks_controller.rb`. No repository write access, GitHub App private key, or Shipit session/API token is needed — only a webhook secret the attacker legitimately possesses for their own onboarded org.

### Recommendation
After signature verification, cross-check that the repository/stack fields the handler is about to act on actually belong to the organization that produced a valid signature (e.g., verify `repository.owner.login`/`full_name` prefix matches the org resolved by `repository_owner`, and reject if not). For `StatusHandler`, scope the `Commit` lookup by the verified repository/org rather than matching `sha` globally.

### Proof of Concept
1. Attacker's org `AttackerOrg` is legitimately onboarded to a shared Shipit instance and knows its own webhook secret (`secret_A`).
2. Attacker POSTs to `/webhooks` with `X-Github-Event: push` and a body:
```json
{
  "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "VictimOrg/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
   signed with `secret_A` via `X-Hub-Signature`.
3. `verify_signature` resolves `repository_owner` to `AttackerOrg`, fetches `secret_A`, and the HMAC validates successfully.
4. `PushHandler#process` reads `repository.full_name = "VictimOrg/victim-repo"` (unrelated to `AttackerOrg`) and calls `stack.sync_github(expected_head_sha: ...)` on `VictimOrg`'s stacks, which the attacker never controlled or was authorized to touch.
5. Equivalently, sending a `status` event with any `sha` forges a commit status on any commit tracked anywhere in the instance via `StatusHandler`, with no repository check at all.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
