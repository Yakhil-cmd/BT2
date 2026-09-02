Confirmed vulnerability found. Let me verify the `PushHandler.process` and `Handler#repository_name`/`#stacks` binding against `WebhooksController#verify_signature`'s `repository_owner` to lock in the exact mismatch.### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while event handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for HMAC verification based on `repository_owner`, a value extracted from the *unverified* JSON body. Every webhook `Handler` then resolves which `Stack`/`Repository` to act on using a *different* field from that same body: `repository.full_name`. The HMAC only proves the raw bytes came from whoever holds the secret associated with `repository_owner` — it says nothing about whether `repository.full_name` (used to pick the target Stack to sync/deploy) actually belongs to that organization. When any onboarded organization has no `webhook_secret` configured (an explicitly supported, optional setting), signature verification is skipped entirely for that organization, letting an anonymous caller forge a payload naming any *other* tracked repository/org and have Shipit act on it.

### Finding Description
`WebhooksController#verify_signature` picks the verifying app purely from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`repository_owner` is computed from `params.dig('repository','owner','login') || params.dig('organization','login')` — fields inside the body the signature is supposed to protect, read out *before* that signature has been validated.

`GithubApp#verify_webhook_signature` treats a missing/blank `webhook_secret` as automatically valid: [3](#0-2) 

Meanwhile, every webhook `Handler` (e.g. `PushHandler`) resolves the `Stack`(s) to act on from a completely different field of the same payload: [4](#0-3) [5](#0-4) 

The binding that should hold is: *the organization whose secret authenticated the request* == *the organization that owns the repository being written to*. Instead, Shipit binds authentication to `repository.owner.login`/`organization.login` while binding the write action to `repository.full_name`, an independent field of the same unauthenticated JSON. Because the signature covers only the raw bytes (not "which field selected the verifying key"), a payload can legitimately claim `repository.owner.login = "org-with-no-secret"` (so verification short-circuits to `true`) while `repository.full_name = "victim-org/victim-repo"` — a stack Shipit does track. `PushHandler#process` then finds and syncs that victim `Stack`, enqueuing `GithubSyncJob` with an attacker-chosen `expected_head_sha`.

### Impact Explanation
This is a cross-tenant/cross-repository write: an unauthenticated caller can trigger `Stack#sync_github` → `GithubSyncJob` → `CacheDeploySpecJob` for a repository/organization they have no relationship to, as long as some organization configured on the shared Shipit instance has a blank `webhook_secret` (a documented, supported configuration state, not a hardening requirement). This can desynchronize another team's stack state, force spurious GitHub API polling using the app's own credentials against an arbitrary tracked repo, and feed attacker-chosen `expected_head_sha` values into the sync/continuous-delivery pipeline — matching the "cross-repository writes" High/Critical impact class.

### Likelihood Explanation
Exploitability depends only on the operational fact that at least one organization onboarded to a shared/multi-org Shipit instance has not set `github.webhook_secret` (README/docs mark it optional), which `GithubApp#verify_webhook_signature` treats as "always verified." No session, API token, or possession of any real webhook secret is required in that case — only knowledge (or a guess) of one onboarded org's login name, which is typically public. In deployments where every org does set a strong secret, this specific path is not exploitable, so likelihood is configuration-dependent but the code contains no structural safeguard tying the two fields together regardless of configuration.

### Recommendation
Verify the signature using the secret associated with the *same* field that handlers use to resolve the target repository (`repository.full_name`'s owner), not a separately-read `repository_owner`/`organization.login` value. Do not allow `verify_webhook_signature` to short-circuit to `true` when `webhook_secret` is blank for multi-organization installs; require an explicit "authentication disabled" opt-in per organization instead. Additionally, after verifying the signature for organization X, reject (or explicitly re-derive `stacks` only from) payloads whose `repository.full_name` does not belong to organization X.

### Proof of Concept
1. Configure Shipit with two organizations: `org-a` (no `webhook_secret` set) and `org-b` (tracked stack, real secret configured).
2. POST to `/webhooks` (no `X-Hub-Signature` needed) with:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
and header `X-Github-Event: push`.
3. `verify_signature` resolves `repository_owner = "org-a"`, looks up `Shipit.github(organization: "org-a")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally.
4. `PushHandler#process` resolves stacks via `payload.dig('repository','full_name') == "org-b/victim-repo"`, finds org-b's real `Stack`, and calls `stack.sync_github(expected_head_sha: "deadbeef...")`, enqueuing `GithubSyncJob` for a repository the caller never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
