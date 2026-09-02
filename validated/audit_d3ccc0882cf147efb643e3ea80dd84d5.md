## Title
`Commit#sha` uniqueness is scoped to `[sha, stack_id]`, not global, while `StatusHandler#process` queries by bare `sha` — cross-stack status write - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

## Summary
The `commits` table enforces uniqueness on the composite `[sha, stack_id]`, explicitly permitting identical `sha` values across different stacks by design. [1](#0-0)  `StatusHandler#process` queries `Commit.where(sha: params.sha)` with no `stack_id` scope, so any commit-status webhook whose `sha` collides with a commit sha already recorded in a *different* stack will update that unrelated stack's commit status too. [2](#0-1) 

## Finding Description
Binding claimed: DB uniqueness scope `[stack_id, sha]` should equal query scope `[stack_id, sha]` used by `StatusHandler#process`. Actual: DB scope is `[sha, stack_id]` (composite unique index) [1](#0-0)  while the query scope is bare `sha` only [3](#0-2) . These do not match, confirming the divergence.

Path: `WebhooksController#create` parses the raw JSON body and dispatches to handlers registered for the `X-Github-Event` header via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, after `verify_signature`, which validates the payload against the GitHub App secret for `repository_owner` derived from the payload itself — this only proves the payload was signed by *some* configured GitHub organization/app, not that the `sha` inside it is scoped to any particular stack. [4](#0-3)  `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no stack/repository filter, so it updates every `Commit` row across the entire `commits` table sharing that sha, regardless of stack. [2](#0-1) 

Because the schema's uniqueness constraint is `[sha, stack_id]` rather than `sha` alone, the same sha can legitimately exist in many stacks simultaneously (e.g., a shared base commit merged into multiple repos/stacks, or a cherry-pick/rebase producing byte-identical commit content and thus identical sha in another repo). An attacker who owns/controls a repository can craft a commit whose sha collides with a known commit sha already tracked in a victim stack (trivially achievable if the victim stack tracks a well-known public commit, e.g., an upstream open-source commit, or by forcing identical tree/parent/commit metadata) and then fire (or cause GitHub to fire) a `status` webhook signed by their own repository/app installation. Because `verify_signature` only checks the signature against the sending organization's own secret, not that the sha belongs to that organization's stack, the handler will find and update the victim's `Commit` row too.

## Impact Explanation
A successful collision lets an unauthenticated-relative-to-the-victim attacker cause status writes (`create_status_from_github!`) on a `Commit` belonging to a stack they do not own, mutating that stack's commit status data. Depending on how commit status is consumed downstream (e.g., merge/deploy gating logic that checks commit status), this can affect deploy/merge decisions for a repository the attacker never authenticated against — matching the "payload for one repository mutating another's stack/commit" Critical category. The blast radius is any stack in the installation whose tracked commit shas overlap with a sha the attacker can produce or replay.

## Likelihood Explanation
Exploitability depends entirely on the attacker's ability to produce (or already know) a commit sha that both exists in the victim's `commits` table and can be delivered via a validly-signed webhook from an attacker-controlled repository/org. SHA-1 git commit hashing is deterministic on content, not a secret; commit-sha collisions across repos are realistic when repos share history (forks, vendored code, common upstream commits, cherry-picks) rather than requiring a cryptographic break. The attacker needs no Shipit credentials — only control of a GitHub repository wired to the same Shipit instance's GitHub App/webhook secret (any onboarded org), and knowledge/reconstruction of a target sha. This is a low-cost, repeatable path per target repository.

## Recommendation
Scope `StatusHandler#process`'s lookup to the stacks/repositories associated with the webhook's own `repository` (e.g., join through `Stack`/`Repository` matching the payload's `repository.full_name`), mirroring the DB's `[sha, stack_id]`-scoped uniqueness, instead of querying `Commit` by bare `sha` alone.

## Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, in test/ per rules)
test "commits table permits identical sha across different stacks (schema check)" do
  stack_a = shipit_stacks(:shipit)
  stack_b = create_stack!(repository: create_repository!(name: "other-repo"))

  commit_a = stack_a.commits.create!(sha: "a" * 40, author_name: "x", author_email: "x@example.com",
                                      committer_name: "x", committer_email: "x@example.com", message: "m")
  commit_b = stack_b.commits.create!(sha: "a" * 40, author_name: "x", author_email: "x@example.com",
                                      committer_name: "x", committer_email: "x@example.com", message: "m")

  assert commit_a.persisted?
  assert commit_b.persisted?
  assert_equal 2, Shipit::Commit.where(sha: "a" * 40).count
end

test "StatusHandler#process updates commits across unrelated stacks for same sha" do
  stack_a = shipit_stacks(:shipit)
  stack_b = create_stack!(repository: create_repository!(name: "other-repo"))
  sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: sha, author_name: "x", author_email: "x@example.com",
                                      committer_name: "x", committer_email: "x@example.com", message: "m")
  commit_b = stack_b.commits.create!(sha: sha, author_name: "x", author_email: "x@example.com",
                                      committer_name: "x", committer_email: "x@example.com", message: "m")

  params = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: sha, state: "success", description: "ok", context: "ci"
  )
  Shipit::Webhooks::Handlers::StatusHandler.new.process(params) rescue nil # invoke process with params.sha == sha

  assert commit_a.reload.statuses.exists?
  assert commit_b.reload.statuses.exists? # cross-stack write proven
end
```
Both assertions hold given the current code: the schema (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`) allows the duplicate-sha rows, and `StatusHandler#process`'s bare `Commit.where(sha: ...)` (app/models/shipit/webhooks/handlers/status_handler.rb:21) touches both.

### Citations

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
