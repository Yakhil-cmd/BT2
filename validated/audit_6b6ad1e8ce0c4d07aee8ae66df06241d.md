### Title
`StatusHandler#process` writes commit statuses by global SHA lookup without validating the payload's repository/owner binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to verify a webhook using only `params.dig('repository','owner','login')` [1](#0-0) , but the `status` event is then dispatched to `Shipit::Webhooks::Handlers::StatusHandler`, whose `process` method resolves the target commit with an unscoped, global `Commit.where(sha: params.sha)` query [2](#0-1) . Unlike every other handler in the codebase, `StatusHandler` never scopes the lookup to the repository/owner named in the authenticated payload.

### Finding Description
The binding that should hold is: **organization whose `webhook_secret` verified the request (`repository.owner.login`) == organization owning the `Commit`/`Stack` being mutated**. `verify_signature` establishes only the first half of this equality — it picks `Shipit.github(organization: repository_owner)` and checks the HMAC signature against that org's secret [1](#0-0) . It never re-checks that any commit/stack the handler subsequently touches actually belongs to that same organization.

`StatusHandler`'s param schema doesn't even require a `repository` object — only `sha`, `state`, and optional fields [3](#0-2) , and `process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
`Commit.sha` is only unique per `stack_id`, not globally (`add_index :commits, %i(sha stack_id), unique: true`) [4](#0-3) , so this query can match commits belonging to arbitrary stacks/repositories/organizations, not just the one that authenticated the webhook.

This is a genuine divergence from the rest of the codebase's design: the base `Handler` class provides a `stacks` helper explicitly built for this purpose — `Repository.from_github_repo_name(repository_name)&.stacks || Stack.none`, scoped by `payload.dig('repository','full_name')` [5](#0-4) . `PushHandler` [6](#0-5)  and `CheckSuiteHandler` [7](#0-6)  both use `stacks.where(...)` to correctly scope their side effects to the authenticated repository. `StatusHandler` is the outlier that bypasses this scoping and hits `Commit` directly and globally.

Once a matching `Commit` row is found (potentially belonging to OrgB's stack), `commit.create_status_from_github!(params)` writes a new `Status` row via `statuses.replicate_from_github!(stack_id, github_status)` [8](#0-7) , i.e., an attacker who only controls OrgA's webhook secret can inject a status onto OrgB's commit if the target SHA is known/guessable/collides.

**Why this is only a partial finding rather than open-and-shut**: exploitation requires the attacker to know (or produce a collision for) the exact 40-character SHA of a commit that already exists in OrgB's Shipit-tracked stack. Git SHAs are not secret — they are public git history, PR metadata, commit messages, etc. — so for public repositories tracked by Shipit, an attacker can trivially learn valid target SHAs (e.g., by browsing OrgB's public repo on GitHub) without any privileged access. This satisfies the "attacker action" preconditions in the prompt (attacker only needs a webhook secret for their own org, which is a legitimate configuration precondition, not a privilege escalation from Shipit's perspective).

### Impact Explanation
An attacker who legitimately controls a GitHub App/webhook secret for OrgA (a tenant already onboarded to the shared Shipit instance) can forge a `status` webhook that is correctly signature-verified for OrgA but writes a `Status` record against a `Commit` belonging to OrgB's `Stack`. This is a cross-tenant data integrity violation: OrgB's CI/deploy-gating status (used in `Commit#state`, `#deployable?`, and to unblock/gate deploys, e.g., `blocking_statuses`, `required_statuses` in `stack.rb`) can be manipulated by an unrelated tenant, potentially forging a "success" status to unblock a deploy that should be blocked, or forging failures to grief a competitor's CI. This matches "a payload for one repository mutating another's stack, commit, task or team" — Critical severity. The blast radius is any multi-tenant Shipit instance where more than one organization's `webhook_secret` is configured (this is explicit as a documented configuration in `Shipit.github`).

### Likelihood Explanation
Preconditions: multi-tenant Shipit instance configured with `webhook_secret` for at least two organizations (OrgA and OrgB), and OrgB's target commit SHA must be known to the attacker — trivial for public repos, and even for private repos, SHAs frequently leak via PR links, CI logs, Slack integrations, etc. The attacker's cost is minimal: they only need what they already legitimately possess (their own org's webhook secret) and knowledge of a target SHA. This is repeatable against any known commit in any tenant, at will.

### Recommendation
Require `repository.full_name` (or `owner.login`) in `StatusHandler`'s param schema and scope the lookup through `stacks` (as `PushHandler`/`CheckSuiteHandler` do), e.g.:
```ruby
stacks.each do |stack|
  stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
end
```
so the SHA lookup is constrained to commits belonging to stacks whose repository matches the payload's (and therefore the signature-verified) organization/repository.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":status from orga does not create a status on shopify's commit" do
  request.headers['X-Github-Event'] = 'status'
  foreign_commit = shipit_commits(:first) # belongs to shipit_stacks(:shipit), owner "shopify"

  # GithubHook.any_instance.stubs(:verify_signature).returns(true) already stubs signature success (setup)
  body = {
    'sha' => foreign_commit.sha,
    'state' => 'success',
    'repository' => { 'owner' => { 'login' => 'orga' }, 'full_name' => 'orga/some-repo' }
  }.to_json

  assert_no_difference 'foreign_commit.statuses.count' do
    post :create, body:, as: :json
  end
end
```
Given the current implementation of `StatusHandler#process` (`Commit.where(sha: params.sha)` with no repository/owner scoping), this assertion **fails** — a status is created on `foreign_commit`, which is bound to `shipit_stacks(:shipit)` (owner "shopify"), even though the payload's `repository.owner.login` is `"orga"`. This demonstrates the broken binding: `repository_owner` used for signature verification ("orga") != the actual owner of the mutated commit ("shopify").

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

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
