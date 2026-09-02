### Title
`StatusHandler#process` writes CI status by bare SHA with no repository scoping, letting one authenticated repository/org mutate another stack's commit status - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `commit.create_status_from_github!(params)` on every match, never checking that the commit's stack belongs to the repository that authenticated the webhook. Unlike every other handler (`PushHandler`, `PullRequest::*Handler`), which resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and scope through `repository.stacks`/`review_stacks`, `StatusHandler`'s param schema does not even `require :repository`, so nothing in the class ties the write to the sender's repo.

### Finding Description
The invariant that should hold is: `status.repository == commit.stack.repository.github_repo_name` for every `Status` record created from an inbound webhook. Tracing the code:

- `Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) validates the HMAC signature using `Shipit.github(organization: repository_owner)`, i.e. a secret keyed by **organization**, not by individual repository. [1](#0-0) 
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
with no filter on `payload['repository']['full_name']`. [2](#0-1) 
- Contrast with `PullRequest::OpenedHandler#repository`, which explicitly resolves and scopes via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before doing anything - the pattern `StatusHandler` should follow but doesn't. [3](#0-2) 
- `Commit#create_status_from_github!` → `add_status` then applies the forged status unconditionally to that commit's stack, and if the resulting state is `success`/`pending` it calls `stack.schedule_merges`, i.e. actually attempts to advance that stack's merge/deploy pipeline. [4](#0-3) 

Because `Commit`/`Status` are global tables (a `sha` is not unique per-installation, only conventionally unique per-repo), any webhook signed with a valid secret for **any** organization/repository registered on the Shipit instance can inject a `Status` for a `sha` string that happens to also exist as a commit in a completely different stack's history. Git SHAs of public commits are public information (visible in any PR/branch), so an attacker who legitimately owns/administers one repository connected to the same Shipit instance (and therefore can generate genuinely signed `status` webhooks, e.g. by using GitHub's Commit Status API against their own repo/sha with `context: codecov/project`) can target a `sha` belonging to a victim's stack in a different repository. `verify_signature` only proves "this org/repo owns a valid secret," never "this status belongs to that sha's actual repository," so the guard does not stop the divergence.

The `review_stacks_enabled`/`provision?` precedence issue in `PullRequest::OpenedHandler#provision?` (app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70) is a real, separate operator-precedence bug — `review_stacks_enabled && allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` only gates the `allow_all` branch on `review_stacks_enabled`, so a repo with `review_stacks_enabled: false` but `provisioning_behavior: allow_with_label`/`prevent_with_label` can still auto-provision review stacks. However, this bug is causally **unrelated** to the `StatusHandler` scoping flaw: the victim stack in the described scenario does not need to be provisioned via this code path at all — it can be any pre-existing stack whose commit SHA the attacker knows. Conflating the two does not change the root cause or the fix, and the "review_stacks_enabled false" precondition is not actually required to reproduce the cross-repository status write.

### Impact Explanation
An attacker controlling any repository registered on the shared Shipit instance can write an arbitrary `Status` (state/context/target_url/description) onto a commit belonging to a stack of another tenant/repository, without ever authenticating against that repository. This can flip a required-status gate to `success`, triggering `stack.schedule_merges` and downstream auto-deploy/auto-merge behavior on a stack the attacker never had permission over — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." The attack is repeatable against any known SHA and is not limited to a single victim stack.

### Likelihood Explanation
Preconditions: the Shipit instance must host more than one repository/organization sharing exposure of the same `/webhooks` endpoint (the documented multi-tenant deployment model), and the attacker must control (or have webhook-signing capability for) at least one of those repositories. The target commit SHA must be known, which is trivial for any public repository or any PR the attacker can see. No Shipit session, API token, or victim secret is required — only the attacker's own legitimate webhook signing capability. This is feasible and repeatable at low cost per Shipit installation serving multiple repositories/orgs.

### Recommendation
Scope `StatusHandler` the same way as the other handlers: require `repository.full_name` in the params schema, resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to `repository.stacks.commits.where(sha: params.sha)` (or equivalently join through `Stack` on `repository_id`) instead of a bare `Commit.where(sha: ...)`. Separately, fix the operator-precedence bug in `PullRequest::OpenedHandler#provision?` (and the analogous logic in `LabeledHandler`/`UnlabeledHandler`/`ReopenedHandler`) by parenthesizing so `review_stacks_enabled` gates all three provisioning-behavior branches, not just `allow_all?`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status handler must not update commits belonging to a different repository" do
  victim_repo  = shipit_repositories(:shipit) # owns victim_stack, review_stacks_enabled: false
  victim_stack = create_stack(repository: victim_repo)
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, ...)

  attacker_payload = ExplicitParameters::Parameters.define {
    requires :sha, String
    requires :state, String
    accepts :context, String
  }.parse!(
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "codecov/project",
    "repository" => { "full_name" => "attacker-org/attacker-repo" } # different tenant
  )

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.new(attacker_payload).process
  end
end
```
Binding to assert both sides of: **before** — `victim_commit.statuses.count == 0` and `payload.repository.full_name != victim_repo.github_repo_name`; **after (current code)** — `victim_commit.statuses.count == 1` (fails the invariant, proving the bug); **after (fixed code)** — `victim_commit.statuses.count == 0` (invariant holds). [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
