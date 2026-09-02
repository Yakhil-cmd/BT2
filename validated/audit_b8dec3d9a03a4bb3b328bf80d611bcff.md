### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook using only the raw `sha` from the payload, with no scoping to the repository that signed the webhook. Any repository whose signature verifies for its own owner/org can therefore write an arbitrary `context`/`state`/`description` status onto any `Shipit::Commit` row in the entire database that happens to share that SHA, including commits that belong to a completely different stack/repository.

### Finding Description
The broken binding: the set of commits a webhook from repository `R` is entitled to update should equal `Commit.where(sha: params.sha, stack: { repository: R })`, but the code implements it as `Commit.where(sha: params.sha)` with no repository/stack filter at all: [1](#0-0) .

`Shipit::WebhooksController#create` dispatches the parsed payload to handlers only after `verify_signature`, which authenticates that the payload really came from GitHub for `repository_owner` (`params.dig('repository','owner','login')`), i.e. it proves *who sent the event*, not *which commits that sender may mutate*: [2](#0-1) . Nothing downstream re-checks that the `sha` in the payload belongs to a commit whose `stack.repository` matches the authenticated `repository_owner`/repo. `create_status_from_github!` then unconditionally writes the status and recomputes `deployable?`: [3](#0-2)  and [4](#0-3) .

Required-status gating is computed purely from context string matching, with no repository check either: `Status::Group` fills in `Status::Missing` for any `required_statuses` context not present, and otherwise uses whatever status objects exist for that context: [5](#0-4) .

Exploit flow: attacker owns/controls a GitHub repository (e.g. a fork of the victim's repository, sharing ancestor commit SHAs, or any repository whose commit history happens to include a SHA already tracked as a `Shipit::Commit` for the victim stack). Attacker installs/configures the GitHub App (or has a legitimate webhook secret) for their own repo/org — this only proves attacker owns *their* repo, which `verify_signature` accepts as valid because it checks the signature against `Shipit.github(organization: repository_owner)` for the attacker's own org, not the victim's: [6](#0-5) . Attacker sends a `status` event with `sha` = the shared SHA, `context` = `'ci/important'` (read from victim's public `shipit.yml`/GitHub status API), `state` = `'success'`. `StatusHandler#process` matches the victim's `Commit` row purely by `sha` and writes the forged status, flipping `commit.deployable?` to true for the victim stack.

Existing guards do not prevent this: `verify_signature` only authenticates the sender's own repository/org, not the target commit's ownership; `drop_unhandled_event` and `ExplicitParameters` only validate payload shape; there is no `Repository`/`Stack` scoping anywhere in this path.

### Impact Explanation
A payload that is genuinely and validly signed for repository A can write/forge a CI status (`state`, `context`, `description`, `target_url`) for a commit belonging to repository B's stack, as long as B has a `Shipit::Commit` row with a matching `sha` (trivially achievable via a shared git ancestor/fork history, or any repository containing a copy of the same commit). This directly satisfies "a payload for one repository mutating another's stack/commit" and can flip `Commit#deployable?` to `true`, enabling an unauthorized deploy of a commit that never passed the victim's real required CI check — Critical severity. The attack is repeatable against any stack/commit sha the attacker can discover or share ancestry with, and is not limited to a single victim.

### Likelihood Explanation
Preconditions: attacker needs (a) a repository they control that can send a validly-signed webhook to the Shipit host (satisfiable by installing the configured GitHub App on their own repo/fork, which is a standard, unprivileged action for a GitHub App with public installation), and (b) a commit SHA that exists both in their repo's history and in the victim's tracked `Shipit::Commit` table (trivially true for any commit reachable before a fork point, or for old/shared commits, PR-merge commits, cherry-picks, etc.). No Shipit session, API token, or GitHub secret of the victim is required. This is low-cost and fully repeatable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and the analogous check-run handler) to only commits belonging to stacks whose `repository` matches the authenticated `repository` from the webhook payload, e.g. `Commit.joins(:stack).merge(Stack.where(repository: Repository.from_github_payload(params))).where(sha: params.sha)`, rather than `Commit.where(sha: params.sha)` unscoped across all tenants.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual addition)
test "a status webhook from a foreign repository cannot forge a required status on a victim commit sharing the same sha" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.cached_deploy_spec.stubs(:required_statuses).returns(['ci/important'])
  shared_sha = 'deadbeef' * 5

  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'shared ancestor')

  assert_not victim_commit.deployable?, "precondition: not deployable before forged status"

  # Attacker's payload is validly signed for attacker/foreign-repo, referencing the shared sha
  # and the victim's exact required context.
  Shipit::Webhooks::Handlers::StatusHandler.new.process_test_payload(
    sha: shared_sha,
    state: 'success',
    context: 'ci/important'
  )

  victim_commit.reload
  assert_not victim_commit.deployable?, "status from an unrelated repository must not satisfy the victim's required status"
end
```
Both sides of the binding — "context an authorized CI system for repo R may report" vs. "context this handler accepts from any signed webhook" — diverge because `Commit.where(sha: params.sha)` performs no repository check, confirming the vulnerability.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status/group.rb (L24-32)
```ruby
      def initialize(commit, statuses)
        @commit = commit

        visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
        missing_contexts = required_statuses - visible_statuses.map(&:context)
        visible_statuses += missing_contexts.map { |c| Status::Missing.new(commit, c) }

        @statuses = visible_statuses.sort_by!(&:context)
      end
```
