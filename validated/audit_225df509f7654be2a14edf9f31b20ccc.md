### Title
StatusHandler#process mutates commits across ALL repositories/organizations by SHA alone, ignoring `payload['repository']` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no scoping to the repository/organization that the webhook signature was verified for. A `status` webhook that is genuinely and correctly signed by Org B (owner of R2/S2) will still match and mutate any `Shipit::Commit` row in the entire `commits` table that shares that SHA, including one belonging to Org A's stack S1, because the base `Handler` class's `stacks`/`repository_name` scoping helpers exist but are never used by `StatusHandler`.

### Finding Description
The broken binding: `organization_that_verified_signature (Org B, via Shipit.github(organization: repository_owner))` == `organization_owning_the_mutated_commit/stack (Org A, owner of S1)`. This should hold but does not.

Path: `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) verifies the HMAC signature strictly against `repository_owner` (Org B) taken from the payload, via `verify_signature` [1](#0-0) , then dispatches to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` without any further binding of the payload to Org B's repositories. `StatusHandler#process` then does: [2](#0-1) 
`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped lookup across the whole `commits` table (which has a unique index on `[sha, stack_id]`, not `[sha]` alone, confirming SHAs are expected to repeat across different stacks): [3](#0-2) . The base `Handler` class actually provides exactly the scoping primitive that should have been used — `stacks`, derived from `payload.dig('repository', 'full_name')` — but `StatusHandler` never calls it: [4](#0-3) .

`create_status_from_github!` then writes a `Status` row and triggers `add_status`, which emits `Hook.emit(:commit_status, ...)` and `Hook.emit(:deployable_status, ...)` and calls `stack.schedule_merges` — i.e. it is a real, consequential write that can unblock merges/deploys gated on CI status: [5](#0-4) [6](#0-5) .

Exploit flow: Org A tracks a public commit with SHA `X` in stack S1. Attacker, who legitimately owns/controls Org B and R2 (their own GitHub org/repo, with their own genuinely configured `webhook_secret`), replays or reconstructs the identical Git commit object (same tree, message, author/committer identities and timestamps — trivial for any public/open commit, or achievable by literally forking Org A's repo and using the same commit) so that R2 also contains a commit with the exact same SHA `X` (this is not a cryptographic SHA-1 collision — it's the same content producing the same hash, which is deterministic and requires no secret). The attacker's GitHub then emits (or the attacker crafts and sends) a `status` webhook for R2/SHA `X` with state `success`. This webhook is correctly HMAC-signed with Org B's real `webhook_secret`, so `verify_signature` passes legitimately for Org B. `StatusHandler#process` finds `Commit.where(sha: 'X')`, which returns Org A's commit row (belonging to S1) in addition to (or instead of) any commit in Org B's own stacks, and writes a forged status onto Org A's commit — even though Org B's signature has nothing to do with Org A.

Why existing guards fail: `verify_signature` only proves "this payload's owner org is who it says it is" — it does not, and cannot, bind the payload's SHA to that org's repository ownership of the specific `Commit` row being mutated. `drop_unhandled_event`, `ExplicitParameters` (`requires :sha`, `requires :state`, etc.) and `check_if_ping` are irrelevant to this binding. No model validation, `Repository` format check, or `require_permission!` intervenes because this path is entirely a signed-webhook system path, not an authenticated-user path.

### Impact Explanation
A payload correctly signed by one tenant (Org B) causes a database write — an injected/forged CI status — on a `Commit` belonging to a completely different tenant's stack (Org A's S1). This directly matches the "Critical" category: "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any target repository/stack whose tracked commits' SHAs the attacker can reproduce in a repo they control (any public commit, or any commit the attacker can otherwise learn the full content of), and the forged status can flip CI gating logic (`add_status` → `stack.schedule_merges`), potentially enabling unauthorized merges/deploys for Org A. Blast radius: cross-tenant, not limited to same host binding — any Shipit deployment tracking multiple orgs/apps is affected, since the vulnerable query has no organization/repository filter at all.

### Likelihood Explanation
Preconditions: (1) Shipit tracks at least two stacks whose commits can share a SHA — trivially satisfiable since SHA1 is content-addressed and any public/forkable commit can be reproduced in an attacker-owned repo/org that is also independently onboarded to the same Shipit instance, or where the attacker already has a legitimately configured GitHub App/webhook for their own org; (2) the attacker needs no privileged secret — they only need their own genuine `webhook_secret` for their own org, which they control by definition of owning that GitHub App installation. Attacker cost is low: fork/replicate a commit, then let GitHub (or a custom POST mimicking GitHub, self-signed with their own secret) deliver the status webhook. Fully repeatable per targeted SHA.

### Recommendation
Scope the lookup in `StatusHandler#process` to the repository asserted by the payload (mirroring the pattern already available via `Handler#stacks`), e.g. restrict to `Commit.joins(:stack).merge(stacks).where(sha: params.sha)` or otherwise ensure only commits belonging to stacks under the repository named in `payload['repository']['full_name']` are updated, rather than a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
minitest plan (in `test/models/shipit/webhooks/handlers/status_handler_test.rb`, hypothetical since actual test files are out of scope for this audit but described for reproduction):
1. Create two distinct GitHub App configs for `OrgA` and `OrgB` (as in `test/dummy/config/secrets_double_github_app.yml`), each with its own real `webhook_secret`.
2. Create `Repository`/`Stack` `S1` under `OrgA/R1`, and `Repository`/`Stack` `S2` under `OrgB/R2`.
3. Create `Commit` `c1` in `S1` with `sha = "deadbeef..."` (40 hex chars), state unknown.
4. Build a `status` webhook payload for `OrgB/R2` with the same `sha = "deadbeef..."`, `state: "success"`, and sign it with **OrgB's real `webhook_secret`** using the same HMAC algorithm as `GithubApp#verify_webhook_signature`.
5. POST to `/webhooks` with `X-Github-Event: status` and the correctly computed `X-Hub-Signature` for OrgB.
6. Assert `verify_signature` succeeds (response is not 422) — establishing Org B's binding held.
7. Assert `c1.reload.status.state == "success"` — i.e., **Org A's** commit (`c1`, in `S1`, owned by `OrgA`) was mutated by a webhook whose signature only ever proved authenticity for `OrgB`.
8. Equality check to assert: `signing_organization (OrgB) != owning_organization_of_mutated_stack (OrgA)`, yet the write occurred — proving the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
