### Title
Cross-repository forged `Status` is rendered transparently as legitimate CI state to real operators - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` with no scoping to the webhook's originating repository, so any commit across any stack sharing that SHA receives a `Status` row. `Commit#status`/`CommitSerializer#status` and `deployable?` consume that `Status` indistinguishably from a genuinely-reported CI result, so the forged row is displayed to legitimate operators and factors into real deploy/merge decisions.

### Finding Description
The claimed binding is: `Status#stack_id`/`commit_id` displayed via `Commit#status` to a legitimate operator == a status that operator's own configured CI (`stack.github_repo_name`) actually reported for that stack. This binding is broken.

`StatusHandler#process` iterates every `Commit` matching the incoming SHA regardless of stack/repository ownership: [1](#0-0) 
and calls `commit.create_status_from_github!(params)`, which delegates to `statuses.replicate_from_github!(stack_id, github_status)` using the *victim* commit's own `stack_id`: [2](#0-1) [3](#0-2) 

`verify_signature` in `WebhooksController` only validates that the payload is correctly signed for the webhook secret associated with `repository_owner` (an org-level GitHub App secret), it never checks that the `sha`/commit referenced in the payload actually belongs to that repository: [4](#0-3) 

Once the forged `Status` row exists, every downstream consumer reads it with no marker of provenance. `Api::CommitsController#index` returns `stack.commits.reachable.includes(:statuses)` for the victim's own stack, serialized via `CommitSerializer#status` which calls `object.status.state`: [5](#0-4) [6](#0-5) 

This is scoped to `require_permission :read, :stack`, so a legitimate operator authenticated for the victim stack sees the forged status exactly as they'd see their own CI's status — there is nothing in `Status`, `Commit`, or the serializer that flags rows created via cross-stack SHA collision differently from rows created by the stack's own GitHub repository. The same aggregate value feeds `deployable?`/continuous-delivery scheduling (`Status#schedule_continuous_delivery`, `enable_ci_on_stack`), so this is not a cosmetic display bug — it changes the actual authorization signal used for automated and human deploy decisions.

### Impact Explanation
An attacker who controls a repository already registered in Shipit under an org whose webhook secret is shared (any repo under `Shipit.github(organization: repository_owner)`) can send a `status` webhook naming an arbitrary SHA. If that SHA also exists as a commit in an unrelated victim stack (e.g., via a shared history, cherry-pick, or an SHA the attacker mines/reuses), a forged `success`/`failure` status is written under the victim stack's `stack_id` and displayed identically to genuine CI results to the victim's own operators and via the victim's own read API (`Api::CommitsController`). This directly affects `Commit#deployable?` and can trigger `enable_ci!`/continuous delivery for the victim stack, i.e., an unauthorized deploy decision made on falsified data — matching the Critical category ("a payload for one repository mutating another's stack, commit... or an unauthorized deploy"). This is repeatable against any stack sharing a colliding SHA and requires no read access to the victim's private API.

### Likelihood Explanation
The precondition requiring a real SHA collision between an attacker-controlled repository and a distinct victim stack is the limiting factor: this is trivial for forks/mirrors of the same repository (identical git history, identical SHAs) but not generically exploitable for unrelated repositories. Within Shipit's typical deployment model (multiple stacks/environments per repository, or forks/staging repos sharing history), this precondition is realistic and requires only the ability to push a commit and have Shipit receive/relay a `status` event for it — no privileged Shipit credentials are needed beyond the shared org-level webhook secret already covering the attacker's own registered repository.

### Recommendation
Scope `StatusHandler#process` (and `Commit#create_status_from_github!`/`Status.replicate_from_github!`) to only the stack(s) whose `Repository#full_name` matches the webhook payload's `repository.full_name`, e.g. filter `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner:, name: })` instead of a bare `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status webhook does not write a status to a commit from a different repository sharing the same sha" do
  attacker_stack = shipit_stacks(:shipit) # attacker's registered stack
  victim_stack   = shipit_stacks(:cyclimse) # unrelated repository/stack
  shared_sha = "deadbeef" * 5

  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)
  victim_commit    = victim_stack.commits.create!(sha: shared_sha, ...)

  params = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: shared_sha, state: 'success', repository: { full_name: attacker_stack.repository.full_name }
  )

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.new.process(params)
  end
end
```
This test should currently FAIL (i.e., `victim_commit.statuses.count` increases), proving `Commit.where(sha: params.sha)` in `status_handler.rb` writes across stacks/repositories without ownership verification, and that the resulting `Status` is then surfaced by `Api::CommitsController#index`/`CommitSerializer#status` to the victim's legitimate operators indistinguishably from real CI output.

### Citations

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

**File:** app/models/shipit/status.rb (L23-34)
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

**File:** app/controllers/shipit/api/commits_controller.rb (L8-13)
```ruby
      def index
        commits = stack.commits.reachable.includes(:statuses)
        commits = commits.newer_than(stack.last_deployed_commit) if params[:undeployed]

        render_resources(commits)
      end
```

**File:** app/serializers/shipit/commit_serializer.rb (L17-19)
```ruby
    def status
      object.status.state
    end
```
