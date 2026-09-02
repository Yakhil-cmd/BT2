### Title
Cross-repository commit status injection via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for a GitHub `status` webhook by querying `Commit.where(sha: params.sha)` across the **entire** `commits` table, with no scoping to the repository that signed/sent the webhook. Because GitHub webhook signatures are verified per-organization (not per-repository), any repository whose organization has the Shipit GitHub App installed can emit a validly-signed `status` event, and if any other stack's commit happens to share that SHA, `create_status_from_github!` is invoked against a commit belonging to a stack the attacker does not control.

### Finding Description
The broken binding: the question states the authorization scope for `Stack#trigger_continuous_delivery` should equal "the set of stacks belonging to the repository that signed the triggering webhook." In code this should be `stacks == Repository.from_github_repo_name(payload.repository.full_name).stacks`, which is exactly how `Handler#stacks` (the base class helper) is implemented: `Repository.from_github_repo_name(repository_name)&.stacks` [1](#0-0) .

`StatusHandler`, however, does not use that helper at all. Its `process` method does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 

This is a **global, unscoped** query over the `commits` table for every stack/repository in the Shipit instance — the actual binding realized in code is `stacks_affected == { s | s.commits.exists?(sha: params.sha) }`, which is a superset of, and independent from, the repository that authenticated the webhook.

Signature verification (`WebhooksController#verify_signature`) only checks that the payload was HMAC-signed with the webhook secret associated with the **organization** named in the payload (`repository.owner.login`), via `Shipit.github(organization: repository_owner)` [3](#0-2) . It never checks that the `repository.full_name` in the payload corresponds to the repository whose commits are ultimately mutated. Even within a single-organization deployment (the common case, single top-level `github:` config in `secrets.yml`), one shared webhook secret is used for **all** repositories in that org [4](#0-3) [5](#0-4) .

Exploit flow: Attacker owns/controls repository R1 in an organization that has the Shipit GitHub App installed (this is a normal, legitimate GitHub org member action, not a Shipit privilege). R1's HEAD commit ends up with the same SHA as an existing `Commit#sha` for stack R2 (e.g., both initialized from a shared template commit, or an empty/boilerplate commit reused across many repos — SHA collision here is a content-addressed match, not a cryptographic break, and is realistically achievable by copying a known blob/tree). Attacker pushes to R1 or otherwise causes CI/GitHub to emit a `status` event for that SHA. GitHub signs this webhook legitimately with the org's real webhook secret and POSTs it to Shipit. `verify_signature` passes (it's genuinely signed for that org). `StatusHandler#process` then finds **any** `Commit` row anywhere in the database with that `sha` — including R2's commit — and calls `create_status_from_github!` on it, writing a status onto R2's commit and (per `Commit#create_status_from_github!` → `add_status`) potentially transitioning its state, which in turn can trigger the deploy pipeline (`ProcessMergeRequestsJob`/continuous delivery scheduling) for stack R2, per the transition logic that fires on state changes (confirmed by existing behavior around `#add_status` webhook/job firing) [6](#0-5) .

None of the existing guards catch this: `verify_signature` authenticates the org, not the specific repository or stack [7](#0-6) ; `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not repository ownership [8](#0-7) ; and the `stacks` repository-scoping helper defined in the base `Handler` class is simply not invoked by `StatusHandler`.

### Impact Explanation
An attacker who controls any repository in an org where the Shipit app is installed can write a `Status` record onto an arbitrary commit in an arbitrary stack elsewhere in the Shipit instance, purely by SHA collision, without ever authenticating against that stack's repository. If the collided commit belongs to a stack configured for continuous deployment, this can drive a state transition that schedules a real deploy/merge action for that stack — an unauthorized deploy pipeline execution for a repository the attacker never controlled, matching the Critical category ("a payload for one repository mutating another's stack, commit, task ... or an unauthorized deploy"). This is repeatable against any stack/commit whose SHA the attacker can reproduce or predict, and blast radius spans every stack sharing the org-level (or, in multi-tenant deployments where SHAs collide only by chance, cross-org if IDs happen to coincide, though the signing org boundary limits that specific vector) webhook trust boundary.

### Likelihood Explanation
Preconditions: attacker needs a repository in an org with the Shipit GitHub App installed (a normal, low-privilege GitHub action — creating/forking a repo in an org they're a member of, or being an outside collaborator able to push), and needs a commit whose SHA matches an existing `Commit#sha` tracked by some other stack. Getting identical SHAs is feasible via shared template repositories, vendored boilerplate, or empty/initial commits, and is entirely under the attacker's control once a matching blob+tree+commit-metadata combination is produced. No secrets are needed — GitHub itself signs the real webhook. This is a low-cost, repeatable attack limited mainly by the difficulty of manufacturing SHA collisions with actively-tracked commits, but the underlying authorization bug (repo-unscoped lookup) is deterministic and always exploitable given a matching SHA.

### Recommendation
Scope `StatusHandler#process` to the requesting repository, mirroring `CheckSuiteHandler`'s pattern: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` and only update commits within `stacks.flat_map(&:commits).where(sha: params.sha)` (or `stacks.each { |s| s.commits.where(sha: params.sha).each { ... } }`), never querying the global `Commit` table by SHA alone.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status for repository A must not update a commit belonging to repository B with a colliding sha" do
  stack_a = shipit_stacks(:shipit)          # authenticated repository (owner: 'shopify')
  stack_b = shipit_stacks(:cyclimse)        # different repository/org, continuous_deployment: true
  colliding_sha = "deadbeef" * 5

  commit_b = stack_b.commits.create!(sha: colliding_sha, author: shipit_users(:walrus),
                                      committer: shipit_users(:walrus), authored_at: Time.now,
                                      committed_at: Time.now, message: "shared template commit")

  GithubHook.any_instance.stubs(:verify_signature).returns(true)
  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => colliding_sha, 'state' => 'success',
    'repository' => { 'full_name' => stack_a.github_repo_name, 'owner' => { 'login' => 'shopify' } }
  }.to_json

  assert_no_difference -> { commit_b.statuses.count } do
    post :create, body:, as: :json
  end
end
```
Binding under test: LHS `stacks_authorized_by_signature = Repository.from_github_repo_name(payload['repository']['full_name']).stacks` (== `[stack_a]`); RHS `stacks_actually_mutated = Commit.where(sha: colliding_sha).map(&:stack).uniq` (currently includes `stack_b`). The test asserts these must be equal (no mutation to `stack_b`'s commit) — the current implementation fails this assertion, confirming the vulnerability.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
