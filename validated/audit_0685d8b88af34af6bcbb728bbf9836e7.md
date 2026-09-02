### Title
Webhook signature verification keys off `repository.owner.login` while event handlers act on the independent `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an incoming GitHub webhook against based on `repository.owner.login` (falling back to `organization.login`), but every event `Handler` resolves the `Stack`/`Repository` to actually operate on using the unrelated `repository.full_name` field from the same JSON body. Because these two fields are never cross-checked against each other, an attacker who knows the webhook secret for *any one* organization configured on a shared Shipit instance can forge a signature that is valid for "their" org while pointing the payload's `repository.full_name` at a stack belonging to a completely different organization/repository, causing Shipit to act on that other stack.

### Finding Description
`verify_signature` computes the signing organization from the request body itself: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from `params.dig('repository', 'owner', 'login')` (or the `organization.login` fallback), and `Shipit.github(organization: repository_owner)` picks that organization's configured `webhook_secret` to validate `X-Hub-Signature` against. This only proves "the sender knows organization X's secret" — it says nothing about which repository the payload's business logic will actually touch.

Every webhook `Handler` resolves its target `Stack` from a *different* field, `repository.full_name`: [3](#0-2) [4](#0-3) 

Since `owner.login` and `full_name` are independent, attacker-controlled JSON keys inside the same signed body, nothing prevents crafting a payload where `repository.owner.login` = "org-the-attacker-controls" (used only to pick the verification secret) while `repository.full_name` = "victim-org/victim-repo" (used to select the actual `Stack`/`Repository` acted upon by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, etc.). The HMAC signature is computed over the full raw body and will validate correctly against the attacker's own org secret, because the signature check never inspects `full_name` at all.

This is structurally the same class of bug as the ERC721 report: a value used for a gating/authorization computation (`utilizationRate` capped by `reserves`, here "which org authorized this webhook") diverges from the value that the same code path actually acts upon (supply rate applied to real balances, here "which repository/stack gets mutated"), and no explicit invariant ties the two together.

### Impact Explanation
On a Shipit instance hosting multiple GitHub organizations (a supported, documented configuration — see `config/secrets.development.shopify.yml` listing multiple orgs, each with its own `webhook_secret`), this allows cross-organization writes: an attacker who is a legitimate org admin/webhook operator for one onboarded organization can forge events that mutate stacks belonging to a different organization — e.g. spoofing `push` events to trigger `GithubSyncJob`/commit ingestion on another org's stack, spoofing `status` events to inject fake CI status on another org's commits (`StatusHandler#process` → `commit.create_status_from_github!`), which can gate or unblock deploys, or spoofing `check_suite`/`pull_request` events that drive merge/deploy automation. This crosses the "cross-repository writes" / unauthorized-deploy-adjacent boundary called out as in-scope High/Critical impact.

### Likelihood Explanation
Requires the attacker to legitimately control (or know the webhook secret of) at least one organization already configured in the shared Shipit instance — a realistic scenario for any multi-tenant/self-service Shipit deployment where distinct teams/orgs are onboarded with separate secrets. No GitHub App private key, `api_clients_secret`, or session is needed; only the ability to send an arbitrary HTTP POST with a correctly computed HMAC over an attacker-crafted JSON body.

### Recommendation
Bind the field used for authentication to the field used for the write. Concretely: after selecting `repository_owner`/`organization.login` and verifying the signature, also verify that this same value matches the owner portion of `repository.full_name` (and `organization.login` when both are present) before dispatching to handlers; alternatively, derive the target repository strictly from the same field used to pick the verification secret, and reject payloads with inconsistent owner references.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` (attacker-controlled, attacker knows `webhook_secret_A`) and `orgB` (victim, has a stack `orgB/victim-repo`).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": {
       "owner": { "login": "orgA" },
       "full_name": "orgB/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, body)` and POSTs to `/github/webhooks`.
4. `WebhooksController#verify_signature` reads `repository_owner` = `"orgA"` [2](#0-1) , fetches `orgA`'s secret, and the signature validates successfully.
5. `PushHandler#process` (via `Handler#stacks`) resolves the target using `repository.full_name` = `"orgB/victim-repo"` [5](#0-4) , and triggers `stack.sync_github` on org B's stack — despite the signature never having been validated against org B's secret.

Note: I was not able to fully trace every downstream handler (e.g. merge/deploy automation triggered by `check_suite`/`pull_request` events) to quantify the maximum blast radius per handler type within the available index; the core signature/target-field mismatch in `WebhooksController` and `Handler` is confirmed directly from source.

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
