### Title
Webhook signature verification keys off `repository.owner.login`, but every event handler acts on unrelated payload fields (`repository.full_name`, `sha`, `organization.login`) — cross‑repository status/sync forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This is a structural analog of the LayerZero refund-address bug: a value used to authorize/verify an action (`repository.owner.login`, which selects the GitHub App/`webhook_secret` used for HMAC verification) is not the same value that the resulting code path actually acts on (`repository.full_name` for stack lookup, or a global `sha` lookup with no repository scoping at all). Nothing enforces that these two payload fields, read independently from the same attacker-supplied JSON body, refer to the same repository/organization.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/secret to verify the HMAC signature with, based solely on `repository_owner`, which is read from the JSON body itself: [1](#0-0) [2](#0-1) 

The HMAC check only proves "this body was signed by the organization named in `repository.owner.login` (or `organization.login`)" — it says nothing about whether the *rest* of the body (in particular `repository.full_name`, `ref`, `after`, or a bare commit `sha`) actually belongs to that organization.

Every downstream handler, however, resolves its target using a *different* field of the same untrusted body:
- `Handler#stacks` looks up the target `Repository`/`Stack` via `payload.dig('repository', 'full_name')`, not the owner login used for signing: [3](#0-2) 
- `PushHandler#process` triggers `stack.sync_github(expected_head_sha: params.after)` for whatever stack that lookup returns: [4](#0-3) 
- `CheckSuiteHandler#process` uses the same `stacks` lookup (via `repository.full_name`) plus attacker-supplied `head_sha`/`head_branch`: [5](#0-4) 
- `StatusHandler#process` doesn't even scope by repository at all — it matches on a **global** `Commit.where(sha: params.sha)`, i.e. any commit tracked by any stack in the entire Shipit instance: [6](#0-5) 

Additionally, `verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for the selected organization: [7](#0-6) 

`Repository.from_github_repo_name` performs a plain DB lookup with no cross-check against the org that was authenticated: [8](#0-7) 

**The broken binding, as an equality that must hold but is never checked:**
`organization authenticated by HMAC (repository.owner.login / organization.login)` == `repository actually written to (repository.full_name used by Handler#stacks, or the globally-matched commit sha in StatusHandler)`.

Before the attack, these two derived values are equal for legitimate GitHub-originated webhooks (GitHub always sends a consistent `repository` object). After the attack, an unprivileged sender who controls the webhook signing secret for *any one* organization configured in this Shipit instance (or one whose `webhook_secret` is left blank, which `docs/setup.md`/`config/secrets.*.yml` show as an explicitly supported/optional configuration) can set `repository.owner.login` to that organization while setting `repository.full_name` (or the bare `sha`) to point at a completely unrelated stack/commit tracked under a different organization.

### Impact Explanation
Because `StatusHandler` has no repository binding at all, an attacker who is a legitimate but unprivileged webhook sender for **any** org/app hosted in this multi-tenant Shipit instance (see the documented `Using Multiple Github Applications` setup) can forge a signed `status` event and inject a fabricated green CI status (`state: "success"`) onto **any commit belonging to any other stack**, regardless of which repository/org that commit belongs to: [9](#0-8) 
Since deploy eligibility, merge-queue mergeability, and continuous-deployment triggers in Shipit are driven by commit status records, this can be used to make an unrelated, victim-owned commit appear CI-green and eligible for merge/deploy — an unauthorized-deploy-class impact reachable purely by forging a webhook body field that verification never covers. `PushHandler`/`CheckSuiteHandler` similarly let the attacker point cross-repository actions (forced `sync_github` calls, forced check-run refresh with attacker-chosen `head_sha`) at a victim stack whose owning organization the attacker never authenticated as.

### Likelihood Explanation
Requires only that the attacker be a legitimate webhook-signing party for one org configured on the shared Shipit instance (or that any configured org has a blank `webhook_secret`, which is an explicitly documented/supported configuration) — no repository write access, no `ApiClient` token, and no session are needed. Crafting the payload is trivial (raw HTTP POST with a custom JSON body); the divergent-field pattern is exactly the reported bug class (an authorized identifier vs. an acted-upon identifier drawn from the same unauthenticated document).

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, derive the organization/repository used for verification and the one used for locating the `Stack`/`Commit` from the **same** validated source, and explicitly assert that the two match (or better, resolve the target `Stack` first, then verify the signature only against the `webhook_secret` belonging to that `Stack`'s own `Repository#owner`, not a value read again from the untrusted body). `StatusHandler` should additionally verify the resolved commit's `Stack`/`Repository` owner equals the organization that produced a valid signature before mutating status.

### Proof of Concept
1. Shipit instance is configured (per `docs/setup.md`) with two orgs, `attacker-org` (attacker is the GitHub App/webhook owner or its `webhook_secret` is blank) and `victim-org` (hosts a tracked `Stack` with commit `deadbeef`).
2. Attacker computes/knows a valid `sha1=` HMAC for `attacker-org`'s secret (or uses no secret at all if blank), and POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{ "sha": "deadbeef", "state": "success", "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" } }
```
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates the HMAC using attacker-org's own (known/blank) secret — passes.
4. `StatusHandler#process` runs `Commit.where(sha: "deadbeef")` — a global, unscoped lookup — and calls `create_status_from_github!` on the victim's commit, forging a "success" status for `victim-org`'s stack despite the attacker never having authenticated as `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** docs/setup.md (L182-185)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

```
