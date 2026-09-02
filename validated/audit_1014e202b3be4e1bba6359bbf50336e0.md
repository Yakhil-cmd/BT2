### Title
`StatusHandler#process` looks up commits by SHA globally, writing attacker-controlled `target_url`/`description` from repository B into stack A's `Status` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` calls `Commit.where(sha: params.sha)` with no repository scoping, then feeds the raw `ExplicitParameters` payload (including attacker-controlled `target_url` and `description`) straight into `Status.replicate_from_github!`. Because git commit SHAs are content-addressed and reproducible by anyone who can construct an identical commit, an attacker who owns an unrelated repository B can trigger a legitimately-signed "status" webhook for a SHA that also exists in stack A, causing stack A's `Status` record to be created with the attacker's arbitrary string.

### Finding Description
Binding that should hold: `payload.dig('repository','full_name')` (the repository that authenticated/emitted the webhook) `==` `commit.stack.repository.full_name` (the repository whose stack's commit is being annotated with the status). This binding is enforced elsewhere in the engine — `Handler#stacks` explicitly resolves `Repository.from_github_repo_name(repository_name)&.stacks` before touching any stack data: [1](#0-0) 

But `StatusHandler#process` never calls `stacks` or otherwise filters by repository; it queries commits purely by `sha` across the entire instance: [2](#0-1) 

`Commit#create_status_from_github!` then forwards the whole `params` object into `Status.replicate_from_github!`, which persists `target_url`, `description`, `state`, and `context` verbatim, keyed only by `stack_id` (derived from whichever `Commit` record matched the SHA, not from the webhook's repository): [3](#0-2) [4](#0-3) 

`WebhooksController#verify_signature` only checks that the payload is validly signed for the organization named inside the payload itself — it does not check that the named repository is the one that owns the commit being mutated: [5](#0-4) 

Exploit flow:
1. Attacker owns repository B (any GitHub repo where they can push and configure a webhook, or where the Shipit GitHub App is already installed for that org).
2. Attacker finds/produces a commit in repository B whose SHA is identical to a commit already present in stack A (trivial: git SHAs are content-addressed — cherry-picking or copying the exact same tree/parents/author-committer timestamps into their own repo reproduces the same SHA).
3. Attacker sets a commit status on that commit in repository B via the normal GitHub API/UI (using only their own permissions on their own repo) with `target_url: 'javascript:alert(1)'` (or any attacker string) and `description`.
4. GitHub sends a legitimately-signed `status` webhook to the Shipit host, `repository.full_name` = repo B.
5. `verify_signature` passes (correct signature for repo B's org).
6. `StatusHandler#process` ignores the `repository` field entirely, matches `Commit.where(sha: params.sha)`, finds stack A's `Commit` row (same SHA), and calls `create_status_from_github!(params)`.
7. `Status.replicate_from_github!` writes a new `Status` on stack A with the attacker's `target_url`/`description`.

None of the existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema, model validations) check that the commit's owning stack/repository matches the webhook's repository, so the divergence is real.

### Impact Explanation
An attacker who controls an entirely unrelated repository can inject an arbitrary `target_url` (and `description`) into another tenant's (stack A's) `Status` record, which is then surfaced in stack A's own UI/API (e.g., commit status links shown to stack A's team, and via `Status.pending?/success?` used to gate `deployable?`/CI checks that affect stack A's continuous delivery gating). This is a cross-tenant write: "a payload for one repository mutating another's stack/commit," matching the Critical category. It also enables state manipulation that can influence CI-gated deploys (`stack.deployable?`, `schedule_continuous_delivery`) for a stack the attacker never controls, and can be used to plant a malicious link (e.g., `javascript:` URI or phishing URL) shown to stack A's legitimate maintainers as if it came from their own CI. It's fully repeatable against any stack whose commits share a SHA with a repository the attacker controls (achievable at will since SHAs are attacker-reproducible).

### Likelihood Explanation
Preconditions: the attacker needs a GitHub repository they control (own account/fork) with the Shipit GitHub App/webhook active for its organization (a normal configuration, not a Shipit secret), and the ability to reproduce an identical commit SHA to one already tracked by the target stack (trivial via `git cherry-pick`/`git commit --amend` reproducing tree/parents/timestamps, or simply by both stacks importing the same public commit e.g. from a shared upstream/fork lineage — an extremely common real-world scenario for stacks that track forks or mirrors). No Shipit session, API token, or secret is required. Attacker cost is low and the attack is fully repeatable against any stack sharing a SHA namespace with a repo they control.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed handler with the same pattern) to only update commits belonging to stacks of the repository named in the webhook payload, mirroring the `Handler#stacks` helper, e.g.:
```ruby
def process
  stacks.each do |stack|
    commit = stack.commits.find_by(sha: params.sha)
    commit&.create_status_from_github!(params)
  end
end
```
This enforces `payload.repository.full_name == commit.stack.repository.full_name` before any write.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook from repository B cannot set status on a commit belonging to repository A's stack" do
  stack_a = shipit_stacks(:shipit)
  repo_b_full_name = "attacker/unrelated-repo"

  shared_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "shared content")

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'target_url' => 'javascript:alert(document.domain)',
    'description' => 'pwned',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => repo_b_full_name, 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  commit_a.reload
  refute_equal 'javascript:alert(document.domain)', commit_a.status.target_url,
    "repository B's payload must not be able to write stack A's Status.target_url"
end
```
Binding asserted: `payload['repository']['full_name']` (`repo_b_full_name`) must equal `commit_a.stack.repository.full_name` (stack A's repo) before the write is allowed; the test demonstrates that today it does not, and the attacker string lands in stack A's `Status#target_url`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
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
