### Title
`StatusHandler#process` mutates `Commit`/`Status` rows across organizations because `Commit.where(sha:)` is not scoped to the webhook-authenticating repository/organization - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a `status` event using `Shipit.github(organization: repository_owner)`'s `webhook_secret`, which only proves the payload was signed by *some* org's registered GitHub App/organization. `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no filter on `stack_id`, `repository_id`, or organization, so any `Commit` row anywhere in the table sharing that sha gets a new `Status` written, and stack CI/merge-queue side effects fire for it.

### Finding Description
The claimed binding is: `Shipit.github(organization: repository_owner).webhook_secret` authorizes writes **only** to `Commit` rows belonging to `repository_owner`'s stacks, i.e. `authenticated_org == owner_org(mutated_commit.stack)`. Tracing the code shows this does not hold.

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` derives `repository_owner` from the payload and calls `Shipit.github(organization: repository_owner)`, verifying HMAC-SHA1 against that org's `webhook_secret` (`lib/shipit/github_app.rb:76-83`). This proves *who signed the request*, not *which commits it may touch*. [1](#0-0) 
- The `status` event is dispatched to `Handlers::StatusHandler`, whose `process` does a completely global lookup:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 
- The `commits` table only enforces a **composite** unique index `(sha, stack_id)`, confirming the schema intentionally allows the same sha to exist under multiple different stacks/organizations simultaneously: [3](#0-2) 
- Nothing in `StatusHandler`'s `params` schema (`requires :sha`, `:state`, etc.) or in `Commit#create_status_from_github!` re-checks that the commit's stack/organization matches `repository_owner` from the payload; the handler never receives or uses the `repository` field at all. [4](#0-3) 

Exploit flow: attacker registers a Shipit-tracked repository under an org they control (e.g. `attacker/repo`), obtains that org's legitimately-issued `webhook_secret` (as any operator installing the GitHub App would), then POSTs a `status` webhook to `/webhooks` signed with that secret, setting `sha` equal to a commit hash that happens to exist in a *different* org's tracked stack (e.g. via a shared vendored/cherry-picked commit). `verify_signature` passes because the signature is valid for the attacker's own org. `StatusHandler#process` then finds and mutates every `Commit` row across all stacks/orgs sharing that sha, including the victim org's, creating a `Status`, potentially flipping CI state (`add_status`/`enable_ci_on_stack`/`schedule_merges` in `app/models/shipit/commit.rb:366-386`), which can enable auto-merge of the victim's pull requests.

### Impact Explanation
A payload authenticated for org A can create `Status` rows and trigger downstream side effects (`stack.schedule_merges`, `deployable_status` hooks, continuous-delivery scheduling) for org B's commits/stacks, without org B's webhook secret ever being known to the attacker. This is a cross-tenant authentication-bypass class issue: a request authenticated for one repository mutates another repository's CI/merge state, matching the "Critical" category of "a payload for one repository mutating another's stack, commit, task or team." The practical exploitability depends entirely on sha collision across tenants (shared vendored commit, cherry-pick, or fork of same upstream repo tracked as two separate Shipit stacks), which is realistic in monorepo/fork/vendoring workflows.

### Likelihood Explanation
Requires: the attacker to legitimately operate a Shipit-tracked repository/org (attainable by any self-service installer, as stated in the prompt's threat model), and a sha collision between the attacker's own commit history and a victim's tracked stack. Sha collisions are not attacker-controlled in general (git shas are content hashes), so this is not exploitable against an arbitrary victim/arbitrary sha on demand — it requires a real shared commit (fork of the same upstream, shared submodule/vendor commit, or a shared merge base) between attacker's and victim's tracked repositories. Given that precondition, the attack is trivially repeatable (just POST more `status` webhooks with matching sha).

### Recommendation
Scope the `StatusHandler` (and any other handler doing global `Commit`/`sha` lookups) to the repository/stack that authenticated the request: resolve the `Repository`/`Stack` from the payload's `repository.full_name` (as already done via `Repository.from_github_repo_name` elsewhere, e.g. in the pull_request handlers) and constrain the query to `Commit.where(sha: params.sha, stack: repo.stacks)` (or join through `stack.repository`) instead of a bare `Commit.where(sha:)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "status webhook for org A does not create a Status on org B's commit sharing the same sha" do
          org_a_stack = shipit_stacks(:shipit)      # belongs to org "shopify" per fixtures
          org_b_stack = shipit_stacks(:cyclimse)    # different org/repository

          shared_sha = 'deadbeef' * 5
          commit_a = org_a_stack.commits.create!(sha: shared_sha, message: 'a')
          commit_b = org_b_stack.commits.create!(sha: shared_sha, message: 'b')

          params = Handler::Params.new(
            'sha' => shared_sha,
            'state' => 'success',
            'branches' => [{ 'name' => org_a_stack.branch }]
          )

          assert_difference -> { commit_b.statuses.count }, 0 do
            StatusHandler.new(params).process
          end
        end
      end
    end
  end
end
```
This demonstrates that a single `sha`-scoped webhook (authenticated only for org A) writes a `Status` on `commit_b`, which belongs to an unrelated `stack`/organization — asserting `commit_b.statuses.count` changes even though only org A's `webhook_secret` was used to sign the request, proving the described cross-tenant mutation.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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
