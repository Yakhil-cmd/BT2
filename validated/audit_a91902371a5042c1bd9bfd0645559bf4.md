### Title
Webhook signature verification binds the wrong organization key to the payload's `repository.full_name`, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Shipit supports hosting multiple GitHub organizations in one deployment, each with its own `webhook_secret` (`lib/shipit.rb:170-200`, `TOP_LEVEL_GH_KEYS`). The equality that must hold for a webhook to be trusted is: **the organization whose secret signed the request == the organization that owns the repository the handler acts on**. `WebhooksController#verify_signature` breaks this binding.

### Finding Description
`verify_signature` derives the signing organization from the attacker-controlled JSON body itself, then verifies the HMAC against that same body using that organization's secret: [1](#0-0) [2](#0-1) 

`repository_owner` (used to pick which org's `webhook_secret` to verify with) reads `repository.owner.login`. The `create` action, however, dispatches the *entire* parsed payload to handlers unchanged: [3](#0-2) 

Handlers resolve the target repository/stack from a **different** field of the same payload, `repository.full_name`: [4](#0-3) 

and act on it directly (e.g. `PushHandler#process` calling `stack.sync_github(expected_head_sha: params.after)`): [5](#0-4) , or `CheckSuiteHandler` scheduling check-run refreshes for arbitrary stacks/commits: [6](#0-5) .

Because `repository.owner.login` (verification key selection) and `repository.full_name` (the field actually acted on) are two independent, attacker-controlled JSON fields inside the same signed body, an attacker who legitimately controls `webhook_secret` for **Organization A** (e.g., as an admin who configured Org A's GitHub App integration in this multi-tenant Shipit instance) can craft a payload where:
- `repository.owner.login = "org-a"` → used solely to select and verify against Org A's secret (succeeds, since the attacker signs it correctly with a secret they legitimately hold).
- `repository.full_name = "org-b/private-repo"` → never covered by the verification-key-selection logic's trust assumption, yet used unchecked by every handler to locate and mutate stacks (`Repository.from_github_repo_name`).

Nothing in `Repository.from_github_repo_name` re-validates that the resolved repository belongs to the same organization whose secret was used to verify the signature.

### Impact Explanation
This lets a party who legitimately administers one GitHub organization's webhook integration in a shared/multi-tenant Shipit deployment forge webhook events (`push`, `check_suite`, `status`, `pull_request` label/merge events, etc.) against a **different organization's** repositories and stacks they have no authorization over. This crosses the "organization authenticated vs. repository written" trust boundary explicitly in scope, and can drive unauthorized state changes on another org's stacks (e.g., forcing `sync_github`, faking commit statuses that gate deploy eligibility, faking `check_suite`/PR review-stack events) — an unauthorized-deploy-adjacent primitive that meets the High-severity bar ("escalation into authorization it should not have" across a repository/organization boundary it doesn't own).

### Likelihood Explanation
Requires the target Shipit instance to be configured for multiple GitHub organizations (multi-tenant `secrets.github` keyed by org, per `github_app_config`) and requires the attacker to already legitimately hold a `webhook_secret` for at least one of those organizations. This is a realistic operational configuration supported directly by the engine (`TOP_LEVEL_GH_KEYS`, `github_organizations`), and no additional Shipit session, API token, or GitHub App private key is needed — only the webhook secret of any one hosted org, which such an org's own GitHub App admin holds. It does not require the host application to deviate from documented mounting.

### Recommendation
After signature verification, re-validate that `repository.full_name` (and any other repository/organization identifiers the handler will act on) actually belongs to the same organization/owner login that was used to select the verification secret (`repository_owner`), rejecting the request otherwise. Alternatively, verify the signature using the exact GitHub App/organization association resolved independently of attacker-supplied JSON (e.g., via a per-repository or per-installation secret keyed off a value not reused elsewhere in the payload for authorization decisions).

### Proof of Concept
1. Configure Shipit multi-tenant with two orgs, `org-a` and `org-b`, each with distinct `webhook_secret`s (`lib/shipit.rb` `github_app_config`).
2. Attacker holds `org-a`'s `webhook_secret` (legitimately, as its GitHub App admin).
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/private-repo"
  }
}
```
4. Attacker signs the raw body with `org-a`'s secret and sets `X-Hub-Signature` accordingly.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, verifies successfully against `org-a`'s secret.
6. `PushHandler` resolves `stacks` via `repository.full_name = "org-b/private-repo"` (unrelated to the verified org) and calls `stack.sync_github(expected_head_sha: params.after)` on `org-b`'s stack, without `org-b` ever having authorized or signed anything.

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
