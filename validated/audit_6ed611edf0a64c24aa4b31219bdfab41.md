### Title
Cross-repository CI status forgery via unscoped SHA lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates an inbound GitHub `status` webhook against the GitHub App/organization derived from the payload's own `repository.owner.login` field [1](#0-0) [2](#0-1) . Authentication is therefore an equality of "the webhook secret used = the secret configured for the organization named in the payload", proving only that *some* repository under that organization sent the event. However, `StatusHandler#process` never re-checks that binding when it writes the status: it looks up commits purely `by sha`, globally, across every stack/repository in the installation, and attaches the status to whatever it finds [3](#0-2) .

### Finding Description
The trust boundary that should hold is: `organization/repository that authenticated the webhook == repository whose commit records are mutated`. Instead:

1. `WebhooksController#verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` using the untrusted `repository.owner.login` (or `organization.login`) field taken straight from the JSON body, and validates the HMAC signature only against that organization's `webhook_secret` [1](#0-0) .
2. Once the signature checks out, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, whose only enforced parameters are `sha`, `state`, and optional `description`/`target_url`/`context`/`created_at`/`branches` — there is no `repository` or `stack_id` requirement [4](#0-3) .
3. `process` resolves target commits with `Commit.where(sha: params.sha)`, with no `stack_id`/repository filter, and calls `commit.create_status_from_github!(params)` on every match [3](#0-2) .

Because commit SHAs are only 40-hex identifiers scoped conceptually to a single repository's object graph, but Shipit's `Commit` table has no per-repository namespacing enforced at status-ingestion time, any `Commit` record elsewhere in the installation that happens to share a SHA with a commit named in the forged/legitimate webhook will receive the attacker-controlled status (`state`, `description`, `context`, `target_url`). This is realistic whenever two stacks in the same Shipit instance track repositories with shared history (forks, mirrors, template-derived repos, monorepo splits, or repositories that cherry-pick/rebase identical commits) — a common real-world configuration for organizations running Shipit across many repos. An attacker who controls one such repository (in the same or another org configured on the Shipit instance) can push a commit that reproduces a known/observed SHA from a target stack's repository (trivial when repos share ancestry) and then have their own repo's CI emit a `status` webhook for that SHA with a fabricated `state: 'success'`/`context` matching what the target stack requires.

### Impact Explanation
`commit.create_status_from_github!` feeds `Status`, which drives `deployable_status`/`commit_status` hook emission and `Commit#state`, which in turn gates `deployable?`/`schedule_continuous_delivery` and the merge queue's `deployment_checks_passed?` logic [5](#0-4) . Forging a passing CI status onto a victim stack's commit can therefore mark an undeployed/unreviewed commit as deployable and, if continuous deployment or the merge queue is enabled on that stack, trigger an unauthorized deploy or merge of that commit — matching the "Critical: an unauthorized deploy, rollback, or merge" impact bucket.

### Likelihood Explanation
Exploitation requires (a) the attacker's own repository (or org) to be a legitimate, webhook-registered GitHub source for the Shipit instance — no session, API token, or privileged account is needed, only ordinary push/CI access to a repo the attacker already controls — and (b) a SHA collision with a target repository's commit, which is realistic for forked/mirrored/templated repositories that are common in organizations centralizing many stacks in one Shipit instance. This is a moderate-likelihood, structural cross-tenant isolation gap rather than a purely theoretical one, directly analogous to the reported bug class: a value (`stakeBalance` / here, "which repository a status belongs to") that is asserted at one point (authentication) but never re-validated/reduced/scoped at the point where it is actually used to mutate state (`Commit.where(sha:)`).

### Recommendation
Scope `StatusHandler#process` (and any other webhook handler that looks records up purely by GitHub-supplied identifiers like `sha`) to the repository/stack that was actually authenticated for the request — e.g., require and validate `params.repository` against the `repository_owner`/`full_name` used in `WebhooksController#verify_signature`, and filter `Commit.where(sha: params.sha, stack: stacks_for(repository))` instead of a global `sha` lookup. Ensure every webhook handler enforces "the entity whose secret verified the payload" equals "the entity whose records are written," not just at the controller layer but at the point of record lookup/mutation.

### Proof of Concept
1. Configure two stacks in the same Shipit instance: Stack A tracking `victim-org/private-repo` and Stack B tracking `attacker-org/public-fork`, where `public-fork` shares commit history with `private-repo` (e.g., it was forked before privatization, or both derive from a shared template/monorepo split), so a specific commit SHA `abc123...` exists as a `Commit` row for both stacks.
2. As the owner of `attacker-org/public-fork` (no Shipit session/API token needed), configure or trigger a CI system to POST a GitHub `status` webhook to Shipit's `/github/webhooks` endpoint, signed with `attacker-org`'s legitimate `webhook_secret`, containing:
   ```json
   {
     "sha": "abc123...",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "attacker-org" } }
   }
   ```
3. `WebhooksController#verify_signature` succeeds because the signature matches `attacker-org`'s configured secret [1](#0-0) .
4. `StatusHandler#process` runs `Commit.where(sha: 'abc123...')`, matches the `Commit` row belonging to Stack A (`victim-org/private-repo`), and calls `create_status_from_github!`, marking that victim commit as `success` for `ci/required-check` even though `victim-org` never sent this webhook [3](#0-2) .
5. If Stack A has continuous deployment or a merge queue enabled and was only blocked on this check, the forged status now satisfies `deployment_checks_passed?`, resulting in an unauthorized deploy/merge of the victim's commit.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
