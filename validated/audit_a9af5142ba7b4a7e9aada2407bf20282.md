### Title
`StatusHandler#process` writes Status rows for any commit matching `sha`, with no repository/stack scoping tied to the authenticating webhook org - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` across the entire `commits` table and writes attacker-controlled `state`/`description`/`target_url`/`context` onto every matching row, completely ignoring the `repository`/`branches` payload fields and never scoping to the stack belonging to the org whose secret signed the request. This is broader than a same-SHA-across-repos collision problem: it affects every commit row in the database sharing that SHA, regardless of tenant.

### Finding Description
The broken binding: for a Status webhook signed by org A's `webhook_secret`, it must hold that `commit.stack.repository.owner == A` for every `Commit` row a Status gets written to. In the actual code this equality is never checked.

`app/models/shipit/webhooks/handlers/status_handler.rb`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

The `params` schema accepts `branches` and does not even require/use `repository` at the handler level [2](#0-1) . Unlike other handlers, `StatusHandler` never calls the base `Handler#stacks`/`repository_name` helper that would scope by `Repository.from_github_repo_name(payload.dig('repository','full_name'))` [3](#0-2) . So the only gate before a Status is written is `WebhooksController#verify_signature`, which validates the signature against `Shipit.github(organization: repository_owner)` — i.e., it proves the *sender* controls org A's secret, but says nothing about which commit rows in the DB the handler is permitted to touch [4](#0-3) .

Attack: an attacker who owns/controls a GitHub org/repo with its own valid `webhook_secret` registers that repo as a Shipit `Repository`/`GithubHook`, and finds (or engineers, e.g. by mirroring a public commit) a commit whose `sha` also exists in a `Commit` row belonging to a victim stack under a different org B. They send a `status` event to `POST /webhooks` signed with their own org's secret, `X-Github-Event: status`, body `{"sha": "<colliding sha>", "state": "failure", "description": "<forged CI message>", "target_url": "<phishing url>", "context": "ci/whatever", "repository": {"full_name": "attacker/repo"}}`. `verify_signature` succeeds because it only checks against the attacker's own org. `StatusHandler#process` then matches on `sha` alone and calls `commit.create_status_from_github!(params)` on the victim's `Commit` row, writing the forged `state`/`description`/`target_url`/`context` [5](#0-4) .

The test `":state create a Status for the specific commit"` confirms all these fields are taken 1:1 from the payload with no repository check [6](#0-5) . `Repository.from_github_repo_name` is available in the codebase and used for scoping in the base `Handler` class, but `StatusHandler` bypasses it entirely, which is the root cause [7](#0-6) .

Existing guards do not prevent this: `verify_signature` only authenticates the sender as the owner of the org named in the sender's own payload/headers, not as an authority over arbitrary commits with a matching SHA; `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not cross-tenant ownership; there is no `stacks` or branch filter applied in `StatusHandler#process` at all.

### Impact Explanation
An attacker who owns any Shipit-registered repository can write forged CI `Status` rows (`state`, `description`, `target_url`, `context`) onto a commit belonging to a completely unrelated, unauthenticated stack/org, as long as a SHA collision exists between their own repo's commit and the victim's tracked commit. Since `commit.create_status_from_github!` recomputes `commit.state`, this can flip a victim commit's effective CI status (e.g., to `success`), which — per `add_status`/`ProcessMergeRequestsJob` enqueuing behavior seen in the test suite — can trigger merge-queue processing (`ProcessMergeRequestsJob`) or deployable-status webhooks for the victim stack based on entirely forged data [8](#0-7) . This is a cross-repository/cross-tenant write to another org's `Commit`/`Status` records, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Preconditions: the attacker needs their own Shipit-registered repository/org with a valid `webhook_secret` (a normal, low-privilege setup available to any org onboarded to the Shipit instance) and a commit SHA that coincides with one already present in a victim's tracked `Commit` table — this can happen naturally (shared open-source commits, forks, cherry-picks, identical empty/tag commits) or be engineered by pushing an identical tree/commit to a throwaway repo. No Shipit session, API token, or victim secrets are required. The attack is fully repeatable against any SHA collision and does not require guessing the victim's secret at all, only knowing/matching a SHA — a realistic scenario in mono-org / forked-repo environments and feasible via engineered git object identity.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository authenticated by the webhook payload, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
using the base `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) so that only commits belonging to stacks under the repository named in — and authenticated via — the incoming payload's `repository.full_name` can receive a Status. Add a require on `repository` in the `params` schema so the field cannot be omitted.

### Proof of Concept
```ruby
test ":status webhook does not write a Status onto a commit belonging to a different repository sharing the same SHA" do
  attacker_repo = Shipit::Repository.create!(owner: 'attacker-org', name: 'evil-repo')
  attacker_stack = Shipit::Stack.create!(repository: attacker_repo, branch: 'main')
  victim_commit = shipit_commits(:first) # belongs to shipit_stacks(:shipit), different repo/org

  # attacker pushes/engineers a commit with the same sha as victim_commit.sha into their own repo
  attacker_repo.stacks.first.commits.create!(sha: victim_commit.sha, ...)

  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulates attacker's own valid org secret
  request.headers['X-Github-Event'] = 'status'

  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'description' => 'forged',
    'target_url' => 'https://phishing.example.com',
    'context' => 'ci/forged',
    'repository' => { 'full_name' => attacker_repo.full_name, 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  assert_no_difference 'victim_commit.statuses.count' do
    post :create, body:, as: :json
  end
end
```
Given the current implementation (`Commit.where(sha: params.sha).each { ... }`), this assertion fails — a Status row is created against `victim_commit`, confirming the cross-tenant write.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
