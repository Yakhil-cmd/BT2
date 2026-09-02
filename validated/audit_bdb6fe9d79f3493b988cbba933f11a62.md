### Title
Cross-repository commit status forgery via unscoped `StatusHandler` lookup breaks org-authenticated vs. repository-written binding — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the GitHub *organization* named in `repository.owner.login`, but `StatusHandler#process` writes a GitHub commit `Status` by looking up `Commit.where(sha: params.sha)` with **no repository/stack scoping at all**. Any webhook that is validly signed for one organization can therefore write a status onto a commit belonging to a completely different `Stack`/repository, as long as the two happen to share a commit SHA — a plausible collision because `sha` is only indexed/expected unique per `(stack_id, sha)`, not globally.

### Finding Description
`WebhooksController#verify_signature` picks the signing secret based solely on the organization embedded in the payload: [1](#0-0) [2](#0-1) 

This means the *binding the engine actually verifies* is: `signature valid ⇒ payload signed by Shipit.github(organization: repository.owner.login)`. It says nothing about which repository/stack the payload's other fields are allowed to affect.

Every other webhook handler enforces repository scoping through the base `Handler#stacks`, which resolves the target stacks via `Repository.from_github_repo_name(repository_name)` (i.e. `repository.full_name`): [3](#0-2) 

`StatusHandler`, however, bypasses this scoping entirely and resolves target commits solely by SHA, globally across the whole database: [4](#0-3) 

`Commit#sha` is only guaranteed unique per stack (see the migration name `index_commits_on_stack_id_and_sha`), not globally, so two different stacks (potentially belonging to different repositories/organizations onboarded on the same Shipit instance) can contain rows with the same SHA (e.g. shared history from forks/cherry-picks, or two repositories whose CI reports the same upstream commit).

The mismatch is exactly the class of bug in the report: the entity that is cryptographically **authenticated** (the organization owning the webhook secret) is not the same entity that is actually **written to** (any commit anywhere in the instance sharing that SHA). This is the "organization authenticated vs. repository written" binding described in the rules, broken here by `StatusHandler`'s unscoped lookup.

### Impact Explanation
`Commit#deployable?` and the deploy-gating logic depend directly on the state of `Status` rows created by this handler: [5](#0-4) 

and required/blocking statuses are configured per stack via `ci.require` / `ci.blocking` in `shipit.yml`: [6](#0-5) 

Because `StatusHandler` never checks which repository the SHA belongs to, an attacker who can get a validly-signed `status` webhook accepted for **any** organization onboarded on the Shipit instance (their own org, or a repo where they merely trigger a CI status update) can inject a forged `state: success` status for a commit SHA that happens to also exist in a victim stack's commit history. This can flip a currently non-deployable/blocked commit to `deployable?`, enabling deploys or auto-deploys (continuous delivery) of a stack the attacker has no legitimate access to — an unauthorized deploy, which the rubric classifies as Critical impact.

### Likelihood Explanation
Exploitability depends on being able to produce, or otherwise obtain, a validly HMAC-signed `status` payload for at least one organization configured in the Shipit instance (this is a much weaker requirement than repository write access to the *victim* stack — the attacker only needs a foothold, e.g. CI-triggered status events, in an unrelated repo/org sharing the instance), and on finding/causing a SHA collision between the attacker's accessible repository and the victim stack. SHA collisions are not purely theoretical: forked repositories, vendored/cherry-picked commits, and squash-merge patterns commonly produce identical SHAs across repositories tracked by the same Shipit instance. The root cause itself — the missing scoping in `StatusHandler` — is unconditional and always reachable once any validly-signed `status` webhook is delivered.

### Recommendation
Scope `StatusHandler#process` the same way every other handler is scoped: resolve the target `Stack`/`Repository` from `payload.dig('repository', 'full_name')` (as `Handler#stacks` already does) and restrict the `Commit` lookup to commits belonging to that repository's stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Shipit instance hosts two stacks, `stack-attacker` (org/repo attacker has legitimate CI access to) and `stack-victim` (a different, more sensitive stack), both instances of `Commit` sharing a SHA `deadbeef...` (e.g. via a common upstream commit, fork, or cherry-pick).
2. `stack-victim`'s `shipit.yml` requires `ci.require: [ci/important]` for deploys; the corresponding commit currently has no such status and is therefore not `deployable?`.
3. Attacker causes (or forges, if they can obtain the org's webhook secret, or the secret is left unset as documented as "optional" in `docs/setup.md`) a `status` event payload:
   ```json
   {
     "sha": "deadbeef...",
     "state": "success",
     "context": "ci/important",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
   }
   ```
4. `WebhooksController#verify_signature` validates the signature against `attacker-org`'s webhook secret — succeeds, because that is the org the attacker legitimately controls.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which runs `Commit.where(sha: 'deadbeef...')`, matching the row belonging to `stack-victim` (not `stack-attacker`), and calls `commit.create_status_from_github!(params)`, writing a `success` status for `ci/important`.
6. `stack-victim`'s commit now satisfies `deployable?`, allowing an unauthorized deploy/rollback trigger despite the attacker never having any permission on `stack-victim`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** README.md (L444-453)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
  require:
    - ci/circleci
```
```
