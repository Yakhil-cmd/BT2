Based on the investigation, this is a real, valid finding.

### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits to update purely by `sha`, with no scoping to the repository that the webhook signature actually authenticated. Because GitHub commit SHAs are content-addressed and identical across forks/shared history, and because the `commits` table only has a composite index on `(stack_id, sha)` rather than a global unique constraint on `sha`, a webhook validly signed for repository A can mutate the CI status of a commit that actually belongs to stack/repository B.

### Finding Description
The broken binding: the question claims that `repository_verified_by(webhook_secret)` must equal `repository_of(stack_owning_commit)`. Concretely:

`repository_owner_of(signed_payload) == repository_owner_of(stack.commits.find_by(sha: params.sha).stack.repository)`

Tracing the code:

1. `WebhooksController#verify_signature` only checks that the raw body's HMAC matches the `webhook_secret` configured for `repository_owner` (`params.dig('repository','owner','login')`), taken straight from the attacker-controlled payload: [1](#0-0) 
This only proves the payload was signed by *some* legitimately configured GitHub organization/app in Shipit — it says nothing about which specific repository's stack the `sha` inside the payload belongs to.

2. Every other handler (`PushHandler`, `PullRequest::*Handler`) scopes its side effects through `stacks`/`repository`, derived from `payload.dig('repository','full_name')`: [2](#0-1) [3](#0-2) 

3. `StatusHandler#process`, in contrast, never touches `repository_name`/`stacks` at all — it resolves target commits by `sha` alone, across the entire `commits` table, regardless of which repository the verified webhook belongs to: [4](#0-3) 

4. `Commit#create_status_from_github!` then unconditionally creates a `Status` row for whatever commit matched: [5](#0-4) 

5. The database schema does not prevent sha collisions across stacks — the index is `(stack_id, sha)`, not a global unique index on `sha` alone (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), confirming the same sha is expected/allowed to exist in multiple stacks' `commits` tables simultaneously (e.g., forks, mirrored/renamed repositories, or repos that share history).

6. `Status#blocking?` and `Commit#blocked?` then directly consume this attacker-writable state to gate deploy safety: [6](#0-5) [7](#0-6) 

Exploit flow: an attacker who can get their own repository's GitHub App status events signed with the *same* Shipit-configured `webhook_secret` that verifies commits for a victim stack (e.g., they are a member of the org where the app is installed, or they own a fork/shared-history repository under a different org that Shipit is configured to trust) sends a `status` webhook with `sha` equal to a commit shared with the victim stack (an ancestor commit reachable via fork/rebase/cherry-pick) and `state: error`. This flips `blocking?` to `true` for the victim's commit even though the attacker never touched the victim's repository or its stack. Later they send `state: success` for the same sha to un-block it. Neither request needs credentials scoped to the victim org — only a signature valid for *some* organization Shipit trusts, combined with the unscoped `Commit.where(sha:)` lookup.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema in `StatusHandler.params`) only validate signature and payload shape — none of them check that the `sha` being updated actually belongs to a commit whose stack's repository matches the verified `repository_owner`/`repository.full_name` from the same payload.

### Impact Explanation
An attacker can arbitrarily flip `blocking?`/`state` for any commit sharing a sha with one they can address via a signed webhook, without ever authenticating against the victim's specific repository or stack. Since `Commit#blocked?` (consumed by `Commit#deployable?` and deploy safety UI/redeploy gating) walks `stack.commits.reachable...any?(&:blocking?)`, this lets an attacker stall or unblock deploys of a stack they don't own — "a payload for one repository mutating another's stack, commit" — matching the Critical impact category. This is repeatable at will and not bound to a single event; every subsequent status webhook the attacker can get signed can retarget any sha across any stack in the same Shipit installation.

### Likelihood Explanation
Preconditions: victim stack has `blocking_statuses` configured (common for CI gating) and shares at least one commit sha with a repository the attacker controls or can trigger events for (trivial via forking, since unmodified ancestor commits keep identical SHAs). The attacker needs a validly signed `status` webhook for *some* repository trusted by the Shipit instance's configured GitHub App(s) — which is satisfied by owning any repository under an org/installation Shipit already trusts (a very low bar in installations serving multiple teams/orgs, or when GitHub Apps are installed org-wide and any member can push/create repos). No Shipit session, API token, or GitHub org privilege on the victim's specific repo is required.

### Recommendation
Scope `StatusHandler#process` (and any commit lookup driven by webhook `sha`) to the repository that was actually authenticated, mirroring the pattern already used by `PushHandler`/`PullRequest` handlers: resolve `Shipit::Repository.from_github_repo_name(payload.dig('repository','full_name'))`, then only update commits belonging to that repository's `stacks` (`repository.stacks.joins(:commits).where(commits: { sha: params.sha })`), rather than a bare `Commit.where(sha: params.sha)` across the whole table.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or a new `status_handler_test.rb`):
1. Set up two `Repository`/`Stack` fixtures: `victim_repo` (owner `victim-org`) with `blocking_statuses` configured, and `attacker_repo` (owner `attacker-org` or same org) — both configured under GitHub orgs whose `webhook_secret` is known/stubbed in test config (simulating that both orgs are trusted by the same Shipit instance).
2. Create `victim_commit` in `victim_repo`'s stack with `sha = "deadbeef..."` and no attacker-owned commit with that sha needed in `attacker_repo`'s stack — only the `sha` string matters to the current unscoped lookup, plus a `Commit` row must exist matching. Create an `attacker_commit` with the identical `sha` in `attacker_repo`'s stack (simulating shared history via fork).
3. `assert_equal victim_repo.full_name, attacker_repo.full_name` should be **false** (they are different repositories) — establishing the two sides of the binding are not equal.
4. POST a `status` webhook signed correctly for `attacker-org` with `repository.full_name = attacker_repo.full_name`, `sha = shared_sha`, `state: "error"`.
5. Assert: `victim_commit.reload.blocking?` is now `true` and `victim_commit.blocked?`/consumers reflect the block, despite `repository_owner` of the request never matching `victim_repo`.
6. POST a second webhook, same shape, `state: "success"`.
7. Assert: `victim_commit.reload.blocking?` is now `false` — demonstrating the attacker fully controls the victim's blocking state via two requests signed only for their own repository.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```
