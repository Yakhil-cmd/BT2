### Title
Webhook signature verification is bound to an attacker-controlled `repository.owner.login`, letting a request "authenticated" against one (unsecured) GitHub organization forge a CI `Status` for any commit SHA in any other organization's stack, enabling an unauthorized deploy - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret used to authenticate an inbound webhook using `repository_owner`, a value taken straight from the unauthenticated, attacker-supplied JSON body (`params.dig('repository','owner','login')`). The event that actually gets executed — in particular `StatusHandler#process` — never re-checks that the organization used to select the secret matches the repository/commit being mutated; `StatusHandler` looks up commits by `sha` alone, with no ownership scoping at all. This breaks the binding "organization that authenticated == repository that is written," analogous to the referenced oracle report where a downstream trust check (the oracle price) is not actually validated for the object being acted upon.

### Finding Description
In a multi-organization Shipit deployment (an explicitly documented and supported configuration, see `docs/setup.md` "Using Multiple Github Applications"), each organization can have its own `webhook_secret`, which is also explicitly documented as optional (`webhook_secret: # nil` in `config/secrets.development.example.yml` and `test/dummy/config/secrets_double_github_app.yml`).

`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the secret) to verify against using a field taken from the raw, unauthenticated request body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` unconditionally returns `true` when the selected org's `webhook_secret` is blank: [3](#0-2) 

So an attacker can pick any configured organization that happens to have no `webhook_secret` set, put its login in `repository.owner.login`, and the signature check passes trivially — no `X-Hub-Signature` header value is even validated.

Crucially, the org used only for *authentication* has no bearing on what the event handler actually mutates. `StatusHandler#process` resolves target commits purely by SHA, with **no repository/organization scoping whatsoever**: [4](#0-3) 

Compare this to the base `Handler` class, which does have a `stacks`/`repository_name` scoping helper, but `StatusHandler` does not use it: [5](#0-4) 

`Commit#create_status_from_github!` creates a `Status` record directly from the forged webhook fields, with no verification against GitHub's API: [6](#0-5) 

Creating a `Status` triggers `after_commit :schedule_continuous_delivery` and CI-enablement side effects: [7](#0-6) 

And a commit's deployability is driven directly by its (now forged) status: [8](#0-7) 

So the equality that should hold — "the organization whose secret authenticated this webhook == the organization/repository whose state is being written" — is broken: authentication is keyed off `repository.owner.login` (attacker-controlled, and can name *any* configured org, including one without a secret), while the actual write (`Status` creation) is keyed off a bare `sha` with no ownership check at all.

### Impact Explanation
An unauthenticated attacker who knows (or can guess/observe, e.g. via a public repo, PR, or leaked commit hash) a commit SHA belonging to a victim stack can forge a `state: "success"` status for that commit, satisfying `ci.require`/`deployable?` checks. If the stack has continuous deployment or the merge queue enabled, this can trigger `schedule_continuous_delivery`, leading to an **unauthorized deploy** of that commit — matching the required High/Critical impact bar ("an unauthorized deploy, rollback or merge"). This is possible purely because the multi-org webhook-secret feature is per-organization but the code never actually enforces that the authenticating organization corresponds to the object mutated by the event.

### Likelihood Explanation
Likelihood is contingent on the deployment having at least one configured GitHub organization without a `webhook_secret` (an explicitly supported/optional configuration shown in the shipped example configs and docs) alongside at least one other organization/stack the attacker wants to target. Given webhook secrets are optional and multi-org support is a first-class documented feature, this is a realistic operational configuration, not a contrived edge case.

### Recommendation
- Scope `StatusHandler` (and any other handler that doesn't already use `Handler#stacks`) to only touch commits belonging to the stack resolved from `repository.full_name`, not a global `Commit.where(sha:)` lookup.
- Reject webhooks where the organization used for signature verification does not match the organization actually referenced by `repository.full_name` in the same payload.
- Consider requiring a non-blank `webhook_secret` for every configured organization (fail closed) rather than silently returning `true` when unset.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `SecureOrg` (has a `webhook_secret`, owns the target stack/commit) and `OpenOrg` (no `webhook_secret` configured — a supported/documented configuration).
2. Attacker sends, without any valid signature:
```
POST /webhooks
X-Github-Event: status

{
  "repository": { "owner": { "login": "OpenOrg" } },
  "sha": "<known sha of a commit in a SecureOrg-owned stack>",
  "state": "success",
  "context": "ci/required-context",
  "description": "forged",
  "created_at": "2024-01-01T00:00:00Z"
}
```
3. `verify_signature` calls `Shipit.github(organization: "OpenOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request is accepted with no valid HMAC.
4. `StatusHandler.call` runs `Commit.where(sha: params.sha)` and finds the commit belonging to the `SecureOrg` stack (no org/repo scoping applied), then calls `commit.create_status_from_github!(params)`, creating a forged `success` Status.
5. If `ci.require` includes `ci/required-context` and the stack has continuous deployment/merge queue enabled, this forged status makes the commit `deployable?`, which can trigger an automatic, unauthorized deploy.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```
