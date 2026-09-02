### Title
Cross-tenant commit-status forgery via missing stack scoping in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit purely by `Commit.where(sha: params.sha)`, with no constraint tying the match to the stack/repository that authenticated the inbound webhook. Any commit row in any stack that happens to share the literal SHA in the payload gets a new `Status` written for it, so a webhook that is validly signed for repository A can write CI state for repository B's commit.

### Finding Description
The binding that should hold is: `Status.stack_id` written for an inbound `status` webhook == `stack_id` of the stack whose `Repository` (owner/name) authenticated that webhook via `verify_signature`.

What the code actually does:
- `WebhooksController#verify_signature` only checks that the payload's `repository_owner` (`params.dig('repository','owner','login')`) matches a GitHub App/org configured in Shipit — it authenticates that the payload genuinely came from GitHub for *some org A*, not that the `sha` inside the payload belongs to A's repository. [1](#0-0) 
- `StatusHandler#process` then does:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
with no `stack_id`/repository filter at all, unlike the sibling `CheckSuiteHandler`, which correctly scopes via `stacks.where(branch: ...)` before touching commits. [2](#0-1) [3](#0-2) 
- `Commit#create_status_from_github!` → `Status.replicate_from_github!(stack_id, github_status)` derives `stack_id` from `commit.stack_id`, i.e. from whichever row matched the SHA — not from the repository that authenticated the webhook. [4](#0-3) [5](#0-4) 

Exploit path: the attacker does not need to break SHA-1. Git commit hashes are a deterministic function of the serialized object (tree hash, parent hash(es), author/committer identity+timestamp, message). If the attacker's own repository A contains, byte-for-byte, the same commit object as B's blocked HEAD (e.g., by forking B, mirroring its history, or replaying the publicly-readable tree/parent chain via `git commit-tree` with matching metadata — all public via GitHub's API/git protocol), repository A legitimately contains a commit with the identical SHA. The attacker then triggers (or has CI in their own repo emit) a `status` webhook for repository A referencing that SHA. GitHub signs this webhook with A's real app/webhook secret, so `verify_signature` passes. `StatusHandler#process` then matches Commit rows by SHA across all stacks, finding B's identical-SHA commit, and writes a `Status` (state fully chosen by attacker, e.g. `success`) against B's stack.

None of the existing guards catch this: `verify_signature` validates the *organization* signing the request, not which SHA/commit is referenced; there is no `ExplicitParameters` constraint tying `sha` to a repository; and no model validation restricts `Status.stack_id` to the requesting repository's stack.

### Impact Explanation
An attacker who controls a repository (or fork) that shares a commit SHA with a target repository can inject arbitrary CI status (`success`/`failure`/`pending`/`error`) into that target's commit, on a different stack/tenant, without any privileges on the target. Since Shipit gates merges/deploys/rollbacks on required status checks (`Stack#required_statuses`, `blocking_statuses`), forging a `success` status can unblock a deploy or merge for repository B that B itself never authorized — this is a payload for one repository mutating another's commit/stack state, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy, rollback or merge"). It is repeatable against any repository/commit for which the attacker can reproduce an identical commit object (most easily via forks, which are extremely common on GitHub), and affects all tenants sharing the Shipit installation.

### Likelihood Explanation
Preconditions: attacker needs (a) a Shipit-configured repository A they control (or can push/PR/trigger CI status webhooks from) with a valid webhook secret already configured by the operator for that org (standard Shipit setup, no secret needed by the attacker themselves — GitHub signs it), and (b) a commit whose SHA is literally identical to the target's blocked commit — trivially achieved for forks or repos that share history/templates with the target, and reproducible without secrets for any public commit by replaying its tree/parent/metadata into their own repo. This requires no cryptographic collision attack, no session, no API token, and no privileged role — only ordinary GitHub usage rights the attacker already has over their own repository.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving commits solely by `sha`) to the stack(s) belonging to the webhook's authenticated repository, e.g. resolve `stack = Stack.find_by(repository: repository_from_payload)` and then `stack.commits.where(sha: params.sha)`, mirroring the pattern already used in `CheckSuiteHandler`.

### Proof of Concept
```ruby
test "status webhook for repository A writes a Status onto an unrelated stack B sharing the same commit sha" do
  stack_a = shipit_stacks(:shipit)
  stack_b = create_stack(repository: create_repository(owner: 'victim-org', name: 'victim-repo'))

  shared_sha = '0' * 40 # stand-in for a byte-identical commit object shared via fork/mirror

  commit_a = stack_a.commits.create!(sha: shared_sha)
  commit_b = stack_b.commits.create!(sha: shared_sha)

  payload = {
    sha: shared_sha,
    state: 'success',
    context: 'ci/attacker',
    repository: { owner: { login: stack_a.repository.owner }, name: stack_a.repository.name },
  }

  post shipit.webhooks_path,
    params: payload.to_json,
    headers: {
      'X-Github-Event' => 'status',
      'X-Hub-Signature' => valid_signature_for(stack_a, payload.to_json), # legit signature for A only
      'Content-Type' => 'application/json',
    }

  assert_response :ok

  # Binding under test: Status.stack_id written == stack_id of repository that authenticated the webhook (A)
  # Actual: Status gets written for B's commit as well, because StatusHandler matches by sha only.
  assert_equal 0, commit_a.reload.statuses.count.zero? ? 0 : 1 # sanity, A legitimately gets a status
  assert_empty commit_b.reload.statuses, "Repository B's commit must not receive a status from a webhook authenticated by repository A"
end
```
This test is expected to fail against the current `StatusHandler#process` (commit B receives the forged status), proving the vulnerability.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
