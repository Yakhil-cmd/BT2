### Title
`StatusHandler#process` writes CommitStatus to any Commit matching sha with no repository/Stack scoping - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` queries `Commit.where(sha: params.sha)` with no join or filter on the repository/Stack named in the verified webhook payload, then calls `commit.create_status_from_github!(params)` on every row returned. Since `sha` is not globally unique across Stacks and Shipit's `Handler` base class already provides a `stacks` helper scoped to the payload's `repository.full_name` that this handler simply ignores, a validly-signed "status" webhook from an attacker-owned repository can inject a `Status` onto a commit belonging to an unrelated victim Stack whenever the sha strings match.

### Finding Description
The broken binding: `[repository named in the verified payload]` (`payload.dig('repository','full_name')`, used elsewhere via `Handler#repository_name`/`Handler#stacks`, [1](#0-0) ) **should equal** `[repository owning the Commit row that gets written]` (`commit.stack.repository`). It does not, because `StatusHandler#process` resolves the target commit purely by `sha`: [2](#0-1) 

Compare this with `Handler#stacks`, the pattern other handlers (e.g. the `pull_request/*` handlers) use to correctly scope work to `Repository.from_github_repo_name(repository_name)&.stacks`: [3](#0-2) 

`verify_signature` in `WebhooksController` only proves that the payload was signed with the secret of the organization named in `payload['repository']['owner']['login']` — it authenticates *who sent the payload*, not *which commit rows the payload is allowed to affect*: [4](#0-3) 

So the exploit does not require a SHA-1 collision attack. An attacker who legitimately administers repo A (any onboarded, low-value repository) merely needs to learn the sha of a commit that also exists in a victim Stack B's `commits` table (public git shas are not secrets — visible in GitHub UI, PR links, CI logs, etc.). The attacker sends a normally-signed `status` event for repo A with `sha` set to that known victim sha. `Commit.where(sha: params.sha)` matches the victim's `Commit` row (in Stack B) even though the payload's `repository.full_name` is repo A, and `commit.create_status_from_github!(params)` writes a new `Status` (`replicate_from_github!`) tied to that commit's actual `stack_id`: [5](#0-4) [6](#0-5) 

This `Status` creation also triggers `enable_ci_on_stack` and `schedule_continuous_delivery` on the victim's commit/stack: [7](#0-6) 

The existing controller test only verifies that a status webhook updates "the specific commit" it targeted by construction and does not assert scoping to the payload's repository, so this gap is untested: [8](#0-7) 

### Impact Explanation
An attacker with write access to any onboarded repository/app (even a throwaway one) can inject fabricated CI `Status` records (`success`/`failure`/`pending`, arbitrary `context`, `target_url`, `description`) onto commits belonging to an unrelated victim Stack, as long as they know a sha the victim previously synced. This is a cross-tenant write: a payload authenticated for repository A mutates data belonging to repository/Stack B. Because CI status feeds into `commit.state`/`deployable_status` and can enqueue `ProcessMergeRequestsJob`, this can misrepresent a victim's CI state to deploy approvers and potentially unblock merges/deploys gated on green CI — squarely in the "payload for one repository mutating another's ... commit" Critical category. The attack is repeatable against any Stack whose commit shas the attacker can learn, and requires no elevated Shipit privileges, session, or secret beyond the attacker's own repo webhook credentials.

### Likelihood Explanation
Preconditions: the attacker must control (own or administer) at least one repository already onboarded into Shipit with a configured GitHub webhook (a low bar — matches the described threat model of "any org they legitimately administer"). They must also know the sha of a commit in the victim Stack, which is typically public (visible on GitHub, in PR/commit URLs, CI dashboards, chat notifications) rather than secret. No GitHub App private key, `webhook_secret` for the victim, Shipit session, or API token is needed. This makes the attack highly feasible and cheaply repeatable — one crafted "status" webhook per target sha.

### Recommendation
Scope the commit lookup by the Stack(s) belonging to the payload's own repository, mirroring the existing `Handler#stacks` helper, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or more efficiently, join through `Stack`/`Repository` in the `Commit.where` query so only commits whose `stack.repository` matches `repository_name` from the verified payload are updated.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or a new handler test):
1. Create two fixtures: `Stack A` (repository `attacker/repo`) with a `Commit` fixture `sha: "deadbeef..."`, and `Stack B` (repository `victim/repo`, unrelated) with a `Commit` fixture sharing the same `sha: "deadbeef..."`.
2. Stub `GithubHook.any_instance.stubs(:verify_signature).returns(true)` (or stub `Shipit.github(organization: 'attacker').verify_webhook_signature` to return true) so the webhook is treated as validly signed for `attacker/repo`.
3. POST `/webhooks` with `X-Github-Event: status` and body `{ "sha" => "deadbeef...", "state" => "failure", "repository" => { "full_name" => "attacker/repo", "owner" => { "login" => "attacker" } } }`.
4. Assert: `stack_b.commits.find_by(sha: "deadbeef...").statuses.count` increased by 1, i.e. `Status` was created with `stack_id: stack_b.id` — proving a payload authenticated for `attacker/repo` wrote a `Status` onto `victim/repo`'s commit/Stack, violating `[repository named in payload] == [repository owning written commit]`.

### Citations

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
