### Title
`StatusHandler#process` matches commits by SHA alone, letting a status from any repository flip `UndeployedCommit#deploy_disallowed?` for a commit belonging to a different repository/stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` and never checks that the webhook payload's `repository` matches the `Commit`'s own `stack.repository`, unlike `PushHandler`, which correctly scopes lookups through `Handler#stacks` (`Repository.from_github_repo_name(repository_name)`). This lets a validly-signed `status` event from one repository write a `success` `Status` onto a `Commit` that belongs to a completely different repository/stack whenever the SHAs coincide, flipping `Commit#deployable?` and therefore `UndeployedCommit#deploy_disallowed?` to `false` without any relationship between the event's origin and the target stack.

### Finding Description
The binding that should hold is: `deploy_disallowed? == false` implies `stack.deployable? && commit.deployable?` **and** the success status that made `deployable?` true originated from `commit.stack.repository`. In code:

- `UndeployedCommit#deploy_disallowed?` is `!deployable? || !stack.deployable?` [1](#0-0) 
- `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))`, driven purely by `status.state` [2](#0-1) 
- `Commit#reload` clears the memoized `@status`, so any newly created `Status` is picked up on the next `deployable?` evaluation [3](#0-2) 
- `StatusHandler#process` resolves the target commit(s) with no repository check at all: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) 
- Contrast with `PushHandler`, which correctly scopes to the repository named in the payload before touching any stack: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }`, where `stacks` is `Repository.from_github_repo_name(repository_name)&.stacks` [5](#0-4) [6](#0-5) 

`WebhooksController#verify_signature` only proves that the payload was signed with the GitHub App secret for the organization named *in the payload itself* (`repository_owner` = `params.dig('repository','owner','login')`), via `Shipit.github(organization: repository_owner)` [7](#0-6) . It says nothing about which specific repository within that org/installation the event came from, nor does it constrain `StatusHandler` to that repository. Since a GitHub App installation is signed once per organization installation, a genuine, GitHub-originated `status` event from *any* repository covered by that installation (e.g., an intra-org fork or test repo the attacker owns/has write access to) produces a validly-signed webhook. If that repository happens to share a commit SHA with a commit tracked by a *different* stack/repository in the same Shipit instance (a realistic occurrence with forks, subtree merges, or repo migrations that preserve history), `StatusHandler` will attach the attacker's `state: success` status to the victim commit regardless of the mismatched repository, and `UndeployedCommit#deploy_disallowed?` flips to `false` for a commit that was never actually validated by CI in its own repository.

### Impact Explanation
A successfully forged/mis-attributed status causes a `Commit`/`Stack` pair unrelated to the attacker's own repository to become deploy-eligible (`deploy_disallowed? == false`), surfaced directly through `deploy_button`/`redeploy_button` and the API `deploy_state` [8](#0-7) . This is a cross-tenant write: a status event authenticated for one repository/org mutates data belonging to another stack/commit, satisfying the "payload for one repository mutating another's stack, commit ... or an unauthorized deploy" Critical impact category. It is repeatable for any SHA the attacker can produce a real `status` event for, against any stack whose commits share that SHA.

### Likelihood Explanation
Exploitation requires: (1) a Shipit deployment tracking more than one repository/stack where two of those repositories share commit history/SHAs (forks, subtree splits, repo renames/migrations), and (2) the attacker having genuine write/status-creation rights on at least one such repository (satisfiable by "push to a fork you own" or maintain a low-privilege repo in the same org/installation) so that GitHub itself signs and delivers the webhook — no `webhook_secret` or other Shipit secret needs to be known by the attacker. This is a real but circumstantial precondition (shared SHA across independently tracked stacks), which is why it is a design gap in `StatusHandler` rather than a per-request forgery of arbitrary payloads.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: resolve the repository from the payload via `Handler#stacks`/`Repository.from_github_repo_name(repository_name)`, and only apply the status to commits whose `stack` is in that repository's stacks (e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently filter `Commit.where(sha: params.sha)` by `commit.stack.repository == repository_from_payload`), rather than matching by SHA alone across the entire installation/instance.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "a status for repo A does not flip deployable? for a commit belonging to repo B" do
          victim_stack = shipit_stacks(:cyclimse) # tracks a different repository than :shipit
          attacker_repo_name = shipit_stacks(:shipit).repository.full_name

          shared_sha = 'deadbeef' * 5
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim', author: shipit_users(:walrus))

          real_commit = UndeployedCommit.new(victim_commit, index: 0)
          assert_predicate real_commit, :deploy_disallowed? # binding LHS before: true

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => attacker_repo_name, 'owner' => { 'login' => 'attacker-org' } },
            'branches' => []
          }

          StatusHandler.call(payload)

          victim_commit.reload
          undeployed = UndeployedCommit.new(victim_commit, index: 0)

          # Binding under test: deploy_disallowed? should remain true because the
          # success status did not originate from victim_stack.repository.
          refute_predicate undeployed, :deployable?     # FAILS today: becomes true
          assert_predicate undeployed, :deploy_disallowed? # FAILS today: becomes false
        end
      end
    end
  end
end
```
This test calls `StatusHandler.call` directly (bypassing signature verification, matching the audited scenario where a validly-signed event has already reached the handler) and demonstrates the SHA-only lookup mutating a commit in an unrelated stack/repository.

### Citations

**File:** app/models/shipit/undeployed_commit.rb (L39-41)
```ruby
    def deploy_disallowed?
      !deployable? || !stack.deployable?
    end
```

**File:** app/models/shipit/commit.rb (L133-136)
```ruby
    def reload(*)
      @status = nil
      super
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/helpers/shipit/stacks_helper.rb (L21-36)
```ruby
    def deploy_button(commit)
      url = new_stack_deploy_path(commit.stack, sha: commit.sha)
      classes = %W[btn btn--primary deploy-action #{commit.state}]
      deploy_state = commit.deploy_state(bypass_safeties?)
      data = {}

      if commit.deploy_disallowed?
        classes.push(bypass_safeties? ? 'btn--warning' : 'btn--disabled')
        data[:tooltip] = t('deploy_button.hint.blocked') if deploy_state == 'blocked'
      elsif commit.deploy_discouraged?
        classes.push('btn--warning')
        data[:tooltip] = t('deploy_button.hint.max_commits', maximum: commit.stack.maximum_commits_per_deploy)
      end

      link_to(t("deploy_button.caption.#{deploy_state}"), url, class: classes, data:)
    end
```
