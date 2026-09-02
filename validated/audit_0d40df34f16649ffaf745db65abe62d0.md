### Title
Webhook status handler trusts the signing organization without scoping the mutated commit to that organization's repository, enabling cross-tenant status forgery - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook against using an organization name taken from the same untrusted JSON body it is about to authorize, then hands that body to handlers that mutate data with no re-check that the mutated resource actually belongs to that organization. `StatusHandler` in particular looks up the target `Commit` **globally by SHA**, with no repository scoping at all, so a valid signature from *any* organization configured in a multi-tenant Shipit instance is sufficient to write a forged commit status onto a commit belonging to a completely different organization's stack.

### Finding Description
`verify_signature` derives the organization used to pick the webhook secret purely from payload content: [1](#0-0) [2](#0-1) 

The secret used is that organization's own `webhook_secret`, from `Shipit::GithubApp#verify_webhook_signature`: [3](#0-2) 

Once verified, the entire parsed payload is dispatched to handlers unchanged: [4](#0-3) 

Most handlers scope their effect to the repository named in the payload via the `stacks`/`repository_name` helper: [5](#0-4) 

However, `StatusHandler` does **not** use that scoping helper at all — it resolves the target `Commit` by SHA alone, across the entire database: [6](#0-5) 

This breaks the binding: `verified_organization (repository.owner.login used to pick webhook_secret) == organization owning the repository/commit actually mutated (Commit.where(sha:))`. The signature only proves the payload was signed by *some* org's secret — the org named in `repository.owner.login` — but the object written (`commit.create_status_from_github!`) is selected purely by attacker-supplied `sha`, independent of that organization. In a multi-tenant Shipit deployment (multiple GitHub orgs configured via `Shipit.github(organization:)`), an attacker who administers (or otherwise knows the `webhook_secret` for) any one onboarded organization can forge a webhook that is correctly signed for their own org, yet whose `sha`/`state`/`context` targets a commit belonging to an entirely different, victim organization's stack.

### Impact Explanation
Commit statuses are the primitive Shipit uses to gate deploy/merge safety checks (`deployable_status`/required CI contexts). Forging a `state: "success"` status with a required `context` on a victim stack's commit — from an attacker who has no legitimate relationship with that stack or organization — can satisfy Shipit's safety gating and enable an **unauthorized deploy or merge** on a repository/organization the attacker does not control. This matches the Critical impact category of "an unauthorized deploy, rollback or merge" achieved purely through the engine's own webhook trust logic, without any Shipit session, `ApiClient` token, or GitHub write access to the victim repository.

### Likelihood Explanation
Requires only that the Shipit instance is configured with more than one GitHub organization (a normal multi-tenant setup, `Shipit.github(organization: ...)`), and that the attacker knows/controls the `webhook_secret` for at least one of those organizations (e.g., their own onboarded org) — which is a much weaker bar than compromising the victim organization. `CheckSuiteHandler` also derives its filter from payload data but at least scopes through `stacks`/`repository_name`; `StatusHandler`'s complete lack of repository scoping makes it the most directly exploitable instance of the pattern.

### Recommendation
Bind signature verification to the resource being mutated: after selecting `github_app` via `repository_owner`, re-validate inside each handler (or centrally in `Handler`) that any commit/resource acted upon belongs to a `Repository` whose `owner` matches the verified organization — i.e., always resolve targets through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` and cross-check its owner against `repository_owner`, rejecting the webhook if they diverge. At minimum, `StatusHandler#process` should scope `Commit` lookup through `stacks`/the payload's `repository.full_name` rather than a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Shipit instance configured with two organizations: `AttackerOrg` (attacker is an admin, knows its `webhook_secret`) and `VictimOrg` (attacker has no access).
2. Attacker locates a commit SHA belonging to a `VictimOrg` stack that is awaiting a required CI status (e.g., context `ci/required-check`).
3. Attacker sends:
   ```
   POST /webhooks
   X-Github-Event: status
   X-Hub-Signature: sha1=<HMAC computed with AttackerOrg's webhook_secret>
   {
     "repository": {"owner": {"login": "AttackerOrg"}},
     "sha": "<victim-commit-sha>",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
4. `verify_signature` computes `repository_owner = "AttackerOrg"`, loads `AttackerOrg`'s `webhook_secret`, and the signature verifies successfully because the attacker legitimately controls that secret.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of organization — and calls `commit.create_status_from_github!(params)`, injecting a forged `success` status onto `VictimOrg`'s commit, potentially satisfying deploy-gating checks for a stack the attacker never had access to.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
