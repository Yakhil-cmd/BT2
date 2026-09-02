This confirms the vulnerability. `CheckSuiteHandler` and `PushHandler` both scope through the base `Handler#stacks` method, which resolves stacks strictly via `Repository.from_github_repo_name(repository_name)` (`payload.dig('repository', 'full_name')`) as seen in `app/models/shipit/webhooks/handlers/handler.rb:32-38`. `StatusHandler`, however, does not use `stacks` at all — it queries `Commit.where(sha: params.sha)` directly against the entire `commits` table with no repository/stack filter, per `app/models/shipit/webhooks/handlers/status_handler.rb:20-24`. [1](#0-0) [2](#0-1) 

### Title
Cross-tenant commit status injection via unscoped SHA lookup in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` instead of scoping through `stacks` (which is derived from the webhook payload's own `repository.full_name`), so a `status` webhook delivered for Attacker's own repository can attach an attacker-chosen `description`/`target_url` to any commit in Victim's stack that happens to share the same SHA. Other handlers (`PushHandler`, `CheckSuiteHandler`) correctly scope lookups via `Handler#stacks`, confirming this is an inconsistency/bug specific to `StatusHandler`.

### Finding Description
The broken binding: `Status#target_url`/`Status#description` on Victim's commit should equal the values produced by Victim's own CI for that Victim commit, i.e. `victim_status.target_url == victim_ci_payload.target_url`. Instead, after a forged `status` webhook from Attacker's own repository, `victim_commit.statuses.last.target_url == attacker_payload.target_url` becomes true whenever a commit sharing the same `sha` exists in Victim's stack.

Code path: `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which authenticates that the payload was signed with the `webhook_secret` configured for `Shipit.github(organization: repository_owner)` — i.e., it proves the webhook genuinely originated from GitHub for that `repository_owner`'s org, but it says nothing about *which repository/stack* the SHA should be attributed to [3](#0-2) . `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

This iterates over **every** `Commit` record in the entire Shipit database matching that SHA, regardless of which repository/stack the webhook payload names. `Commit#create_status_from_github!` then calls `statuses.replicate_from_github!(stack_id, github_status)` [4](#0-3) , and `Status.replicate_from_github!` persists `description`/`target_url`/`context`/`state` verbatim from the webhook params with no cross-check against the commit's own stack's repository [5](#0-4) .

Contrast with `PushHandler`/`CheckSuiteHandler`, which use `stacks` (scoped by `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) before ever touching commits [6](#0-5) [7](#0-6) . `StatusHandler` skips this entirely, so `verify_signature`'s per-organization authentication is bypassed at the object level: it proves the *sender* org, not that the *target commit's stack* belongs to that org.

Attacker's exact action: Attacker owns (or has push/CI access to) some repository already configured as a Shipit stack under any org, e.g. `attacker-org/attacker-repo`. They cause GitHub to emit a `status` event for a commit SHA that they control the choice of (e.g., by pushing a commit whose SHA collides with, or matches, a known commit SHA already present in Victim's stack — this is feasible in shared-history scenarios such as forks, cherry-picks, or a shared upstream commit merged into multiple stacks) with `description`/`target_url` set to arbitrary attacker content, and creates a commit status via GitHub (using their own CI or the GitHub API on their own repo) targeting that SHA. GitHub signs and delivers this webhook using the webhook secret configured for `attacker-org` — legitimate signing, since it is a real event on a repo Attacker controls. `verify_signature` passes because it only checks that the payload came from `attacker-org`'s GitHub App. `StatusHandler` then writes the attacker's `description`/`target_url` onto the Victim's commit row wherever the SHA collides.

Existing guards fail because: `verify_signature` only authenticates the sending organization, not the target repository per-commit; `ExplicitParameters` schema on `StatusHandler` only validates types/presence of `sha`, `state`, `description`, `target_url`, `context`, not tenant ownership; and unlike other handlers, `StatusHandler` never calls `stacks`/`Repository.from_github_repo_name` to scope by the payload's own `repository.full_name`.

### Impact Explanation
A payload legitimately authenticated for one repository (Attacker's) mutates a `Status` record belonging to a different repository's stack (Victim's) — this is the "payload for one repository mutating another's stack, commit" category described as Critical impact. Concretely, `Status#description`/`Status#target_url` fields rendered in Shipit's commit/stack UI for the Victim's commit are attacker-controlled, enabling forged CI status text and a forged `target_url` link (phishing bait presented as if it were the Victim's own CI system) on Victim's operational UI, and since `Status` also affects `Commit#deployable?`/blocking behavior via `state`, deploy/merge gating decisions for Victim's stack can be influenced by attacker-forged CI state. This is repeatable against any stack whose commit history contains a SHA the attacker can reproduce or predict (shared upstream commits, forks, common base commits across shared library repos), and it is one repeatable HTTP-triggerable action per matching SHA, with no per-victim-repository authorization performed by `StatusHandler`.

### Likelihood Explanation
Preconditions: (1) Attacker must have an actual Shipit-tracked repository under some configured GitHub org/app where they can legitimately trigger `status` events (owning or having write/CI access to that repo, or being able to author commit statuses via API on it); (2) a colliding SHA must already exist in Victim's stack's `commits` table — this is realistic in monorepo/fork/shared-upstream setups common to CI/CD tooling, but not universal. Attacker cost is a normal GitHub push/status-API call on a repo they legitimately control; no Shipit secrets, sessions, or privileged roles are required, and the request is fully repeatable for every future colliding SHA.

### Recommendation
Scope `StatusHandler#process` through the same repository-derived `stacks` relation used by other handlers, e.g. resolve target commits as `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` (or `Commit.where(sha: params.sha, stack_id: stacks.ids)`), so a status webhook can only mutate commits belonging to stacks whose `Repository` matches the payload's own `repository.full_name`.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_test.rb (or similar)
test "status webhook from repo A cannot inject status onto a commit of repo B's stack with the same sha" do
  victim_stack  = shipit_stacks(:shipit)                     # belongs to org/repo "victim/repo"
  attacker_repo_full_name = "attacker/evil-repo"              # unrelated repository
  colliding_sha = "a" * 40

  victim_commit = victim_stack.commits.create!(sha: colliding_sha, ...)

  payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'description' => 'ATTACKER CONTROLLED TEXT',
    'target_url' => 'https://evil.example.com/phish',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_status = victim_commit.reload.statuses.last
  # BROKEN BINDING: victim_status.target_url should equal victim's own CI value, not attacker's
  assert_not_equal 'https://evil.example.com/phish', victim_status.target_url
  assert_not_equal 'ATTACKER CONTROLLED TEXT', victim_status.description
end
```
This demonstrates that `StatusHandler` writes Attacker-chosen `target_url`/`description` onto Victim's commit despite the payload naming an unrelated repository, confirming the equality `victim_status.target_url == attacker_payload.target_url` holds when it should not.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
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
