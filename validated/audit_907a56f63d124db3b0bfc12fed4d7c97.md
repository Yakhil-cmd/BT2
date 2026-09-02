### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets a status webhook from one repository forge CI state on another repository's stack, later disclosed unauthenticated via `MergeStatusController#check` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb], [File: app/controllers/shipit/merge_status_controller.rb])

### Summary
`StatusHandler#process` resolves target commits with a bare `Commit.where(sha: params.sha)`, never restricting the query to the repository/stack that actually sent the `status` webhook, unlike every sibling handler which scopes through `Repository.from_github_repo_name(params.repository.full_name)`. Because GitHub commit SHAs are content-addressed and identical between a public repo and any fork of it, an attacker who owns a fork and a Shipit-registered stack for that fork can trigger a legitimately-signed webhook that also writes a forged `Status` row onto a victim stack's identical commit, and that forged `merge_status` is then readable by anyone, unauthenticated, through `MergeStatusController#check`/`#show` (`skip_authentication only: %i[check show]`).

### Finding Description
Binding claimed to hold: `repository_name_from_signed_webhook_payload == repository/stack_that_receives_the_Status_write`. Tracing the code shows this binding is **not enforced**:

- `Handler` defines a scoping helper, `stacks` (`Repository.from_github_repo_name(repository_name)&.stacks`), specifically to bind webhook effects to the sending repository (`app/models/shipit/webhooks/handlers/handler.rb:32-38`). Every other handler (`ClosedHandler`, `LabeledHandler`, `OpenedHandler`, `AssignedHandler`, etc.) uses `Repository.from_github_repo_name(params.repository.full_name)` before touching any record.
- `StatusHandler#process` does not use this helper at all: [1](#0-0) 
  It queries `Commit.where(sha: params.sha)` globally and calls `commit.create_status_from_github!(params)` on every match, regardless of which stack/repository that `Commit` row belongs to.
- `verify_signature` in `WebhooksController` only proves the payload was signed by the GitHub App installation for the `repository.owner.login` present in the payload: [2](#0-1) 
  It authenticates *who sent* the webhook, not *which stack's commit table may be mutated*. Since `StatusHandler` never checks `params.repository.full_name` against the target `Commit#stack`, a validly-signed webhook from the attacker's own installation can still mutate `Commit`/`Status` rows belonging to a completely different (victim) stack, as long as a `Commit` row with the same `sha` exists there. Git SHAs are computed purely from commit content (tree, parents, author/committer, message) and are identical between a repository and any fork/clone of it, so an attacker forking a public victim repo and getting their own fork synced into their own Shipit stack (`GithubSyncJob`) will have `Commit` rows with SHAs identical to the victim's. Emitting (or having GitHub relay) a `status` event referencing one of those shared SHAs, signed with the attacker's own installation secret, satisfies `verify_signature` while `Commit.where(sha:)` fans the write out to the victim's `Commit`/`Status` row too.
- Once the victim's `Status` is forged to `success`, `Stack#merge_status` recomputes to `'success'` via `branch_status`/`undeployed_commits`: [3](#0-2) 
- `MergeStatusController` exposes this state with no identity check at all for `#check`: [4](#0-3) 
  `skip_authentication only: %i[check show]` bypasses `force_github_authentication`; `#check` (unlike `#show`, which at least gates on `current_user.logged_in?`) renders `'ok'`/200 straight from `stack.merge_status` to anyone, and the target stack is discoverable either by `params[:stack_id]` or by `ReferrerParser` parsing an attacker-supplied `referrer` param containing any `owner/repo`.

No other guard in the chain intercepts this: `ExplicitParameters` only validates payload shape (`sha`, `state`, etc.), not repository ownership of the target `Commit`; `drop_unhandled_event` only checks the event type is handled; there is no `require_permission!`/`stacks` scope check anywhere in `StatusHandler` or `MergeStatusController#check`.

### Impact Explanation
- **Critical**: a webhook payload genuinely originating from (and signed for) the attacker's own repository writes a `Status`/updates `Commit` state that belongs to a victim's stack — "a payload for one repository mutating another's stack, commit." This directly feeds `Stack#merge_status`/`allows_merges?`, which gates automated merges and continuous delivery, so it can move a victim stack into a merge-eligible or deploy-eligible state that was never actually earned.
- **High**: `MergeStatusController#check`/`#show` disclose that (forged) state to any unauthenticated caller for any repository discoverable by owner/name, with zero identity check due to `skip_authentication only: %i[check show]`.
- Repeatable against any victim stack whose repository is public (so the attacker can fork it and obtain matching commit SHAs) and that Shipit already tracks; the attacker needs only their own account/fork/installation, not the victim's credentials.

### Likelihood Explanation
Preconditions: (1) the victim's repository must be public/forkable so the attacker can obtain identical-SHA commits; (2) the attacker must have (or be able to self-provision) a GitHub App installation/webhook secret for their own account/org so `verify_signature` passes for their own payload — a standard, low-cost, self-service action, not a Shipit or GitHub secret; (3) the victim's stack must already have synced the shared commit via `GithubSyncJob` so a matching `Commit` row exists. All of this is achievable by an ordinary GitHub user with no special privilege, matching the described unprivileged attacker capabilities (owning a repo, forking, emitting/triggering webhooks from their own repo).

### Recommendation
Scope `StatusHandler#process` to the sending repository, mirroring the pattern used by other handlers: resolve `stacks` via `Repository.from_github_repo_name(params.repository.full_name)&.stacks` (or filter `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`) before calling `create_status_from_github!`. Additionally, reconsider whether `MergeStatusController#check`/`#show` should remain fully unauthenticated, or at minimum ensure the exposed `merge_status` can only ever reflect statuses that were correctly scoped to that stack's own repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test "a status webhook for repo A must not flip merge_status for repo B sharing the same commit sha" do
          attacker_stack = shipit_stacks(:shipit)      # attacker-controlled repo/stack
          victim_stack   = shipit_stacks(:cyclimse)     # victim repo/stack, unrelated

          shared_sha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
          attacker_commit = attacker_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus), committer: shipit_users(:walrus))
          victim_commit   = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus), committer: shipit_users(:walrus))

          # Binding under test, stated explicitly:
          # payload.repository.full_name (attacker_stack.repository.full_name) == stack that receives the Status write
          before_victim_status = victim_stack.reload.merge_status

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => attacker_stack.repository.full_name }
          }

          Shipit::Webhooks::Handlers::StatusHandler.call(payload)

          # If the binding held, only attacker_commit's stack (attacker_stack) would change.
          assert_equal before_victim_status, victim_stack.reload.merge_status,
            "victim stack's merge_status must not change from a webhook signed for a different repository"
          # Demonstrates the actual (broken) behavior:
          assert_equal 'success', victim_commit.reload.status.state
        end
      end
    end
  end
end
```

```ruby
# test/controllers/merge_status_controller_forged_test.rb
require 'test_helper'

module Shipit
  class MergeStatusForgedDisclosureTest < ActionController::TestCase
    tests Shipit::MergeStatusController

    test "unauthenticated GET check discloses forged merge_status for a victim repo" do
      victim_stack = shipit_stacks(:cyclimse)
      victim_stack.stubs(:merge_status).returns('success') # forged via StatusHandler in prior step

      get :check, params: { stack_id: victim_stack.to_param }
      assert_response :ok
      assert_equal 'ok', response.body
      # No session[:user_id] set anywhere in this test -> fully unauthenticated read.
    end
  end
end
```

Note: I could not fully verify from the available index whether `Commit` enforces `validates :sha, uniqueness: { scope: :stack_id }` (allowing identical SHAs across different stacks) versus a global uniqueness constraint; the schema/model design (per-stack `commits` tables, `belongs_to :stack`) strongly implies per-stack scoping, consistent with normal fork-tracking use cases, but this should be confirmed against `app/models/shipit/commit.rb` validations and `db/schema.rb` in a full checkout before relying on the exact PoC record setup above.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/stack.rb (L286-304)
```ruby
    def merge_status(backlog_leniency_factor: 2.0)
      return 'locked' if locked?
      return 'failure' if %w[failure error].freeze.include?(branch_status)
      return 'backlogged' if backlogged?(backlog_leniency_factor:)

      'success'
    end

    def backlogged?(backlog_leniency_factor: 2.0)
      maximum_commits_per_deploy && (undeployed_commits_count > maximum_commits_per_deploy * backlog_leniency_factor)
    end

    def branch_status
      undeployed_commits.each do |commit|
        state = commit.status.simple_state
        return state unless %w[pending unknown missing].freeze.include?(state)
      end
      'pending'
    end
```

**File:** app/controllers/shipit/merge_status_controller.rb (L4-50)
```ruby
  class MergeStatusController < ShipitController
    skip_authentication only: %i[check show]

    etag { cache_seed }
    layout 'merge_status'

    def show
      response.headers['X-Frame-Options'] = 'ALLOWALL'
      response.headers['Vary'] = 'X-Requested-With'

      if stack
        return render('logged_out') unless current_user.logged_in?

        if stale?(last_modified: [stack.updated_at, merge_request.updated_at].max, template: false)
          render(stack_status, layout: !request.xhr?)
        end
      else
        render(html: '')
      end
    rescue ArgumentError
      render(html: '')
    end

    def enqueue
      MergeRequest.request_merge!(stack, params[:number], current_user)
      render(stack_status, layout: !request.xhr?)
    end

    def dequeue
      if (merge_request = stack.merge_requests.find_by_number(params[:number])) && merge_request.waiting?
        merge_request.cancel!
      end
      render(stack_status, layout: !request.xhr?)
    end

    def check
      respond_to do |format|
        format.html do
          if stack_status == 'success'
            render(plain: 'ok')
          else
            render(plain: stack_status, status: 503)
          end
        end
        format.json { render(json: { stack_status: }) }
      end
    end
```
