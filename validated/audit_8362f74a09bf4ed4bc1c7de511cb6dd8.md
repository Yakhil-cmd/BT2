StatusHandler.rb reveals the strongest analog to the FSD "accrue-without-replenish" bug class: a payload field is trusted and acted upon (`commit.create_status_from_github!`) for **every commit matching the SHA across the entire installation**, without re-verifying that the commit's own `stack`/repository is the same repository whose ownership was used to select the `webhook_secret` in `WebhooksController#verify_signature`.

### Title
Cross-repository commit status forgery via SHA collision in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check based on `repository_owner` (the `repository.owner.login` or `organization.login` field of the incoming payload) [1](#0-0) [2](#0-1) . Once the signature is accepted, `StatusHandler#process` applies the status update to **every** `Commit` row across the whole Shipit instance that shares the given `sha`, with no scoping to the repository/organization that was actually authenticated [3](#0-2) . This breaks the equality: *organization authenticated (`repository_owner` used to pick the GitHub App/secret)* == *repository whose state is written (`Commit.where(sha:)`, unscoped by repository)*.

### Finding Description
`Handler#stacks` (the base class used by `PushHandler`, `CheckSuiteHandler`, etc.) properly scopes lookups through `Repository.from_github_repo_name(repository_name)` before touching a stack's commits [4](#0-3) . `StatusHandler`, however, does not use this scoping at all: it fetches `Commit.where(sha: params.sha)`, which is global across all repositories tracked by the Shipit instance, then calls `create_status_from_github!` on each match [3](#0-2) .

Because git SHAs are content hashes and not globally unique across independent repositories, and because status webhooks only require a `sha`/`state`/optional `context`/`target_url`/`description` fields with no repository ownership check in the handler's `process` method, an organization/repo owner who legitimately owns *any* repository configured in the Shipit instance (with its own valid `webhook_secret` for their own GitHub App config) can send a validly-signed `status` webhook whose payload references a `sha` that happens to also exist as a commit in a completely different tracked repository/stack. `verify_signature` only checks that the payload is authentically signed by *some* configured organization's secret; it does not confirm that the `repository` referenced inside the `status` event actually belongs to that same signing organization for the commit rows being mutated, since `StatusHandler` never consults `repository_name`/`stacks` at all.

This is directly analogous to the FSDVesting bug: the accounting/state-changing action (writing a `Status` for a `Commit`, which downstream drives `Commit#state`, deployability checks, and CI gating for a stack's deploy pipeline) is performed against a resource (an unrelated repository's commit) that was never covered by the authorization/verification binding (the signing organization owning that repository).

### Impact Explanation
This maps to the "unauthenticated write into another organization's tracked stack state" category. A `Status` write can flip a `Commit`'s CI/deployability state (success/failure/pending), which downstream is consumed by `Commit#deployable?`/merge/deploy-gating logic used to decide whether a revision is eligible for deploy. An attacker able to author a `status` webhook for their own onboarded repository (something requiring no special privilege beyond controlling a repository's CI within an org that already has a Shipit GitHub App configured) can, on SHA collision, corrupt CI status confidence for another tracked stack's identical/colliding commit — a cross-repository state write that crosses the trust boundary the webhook signature is meant to enforce (organization-scoped write authority).

### Likelihood Explanation
Exploitation requires the attacker to find or engineer a commit SHA collision between their own repository and the victim's tracked repository, which is a significant practical constraint (SHA-1 is currently only weakly broken via chosen-prefix collision attacks with meaningful engineering effort, not something achievable casually). Full-strength exploitation likelihood is Low, but the underlying code defect — a webhook handler mutating global-namespace state (`Commit.where(sha:)`) without any repository ownership scoping, unlike its sibling handlers — is a real, concrete violation of the intended trust binding and warrants remediation independent of SHA-collision feasibility.

### Recommendation
Scope `StatusHandler#process` the same way `Handler#stacks` scopes `PushHandler`/`CheckSuiteHandler`: restrict the `Commit` lookup to commits belonging to `stacks` (i.e., commits whose `stack` is derived from `Repository.from_github_repo_name(repository_name)`), e.g. `Commit.where(sha: params.sha, stack: stacks)... .each { |commit| commit.create_status_from_github!(params) }`, so that a validly-signed webhook can only mutate commit state within the repository it was actually signed for.

### Proof of Concept
1. Configure two GitHub organizations/apps in `secrets.yml`, `org-victim` (owns tracked stack `victim/repo`) and `org-attacker` (owns tracked stack `attacker/repo`), each with its own `webhook_secret`.
2. Ensure (via engineered SHA-1 collision, e.g. chosen-prefix collision techniques) that a commit SHA `S` exists both in `victim/repo`'s tracked `Commit` table and is a valid commit reachable in `attacker/repo`.
3. From `org-attacker`'s repository, trigger/forge a `status` event for commit `S` (signed with `org-attacker`'s legitimate `webhook_secret`) with `state: "failure"`.
4. `WebhooksController#verify_signature` succeeds because the signature is valid for `org-attacker` [1](#0-0) .
5. `StatusHandler#process` updates the `Status`/state of **every** `Commit` with `sha: S`, including the one belonging to `victim/repo`'s stack, despite the request never being authenticated for `org-victim` [3](#0-2) .

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
