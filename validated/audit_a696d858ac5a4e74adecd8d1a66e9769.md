### Title
Cross-tenant Status write via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by `sha` alone, across the entire `commits` table, and never restricts the query to the repository named in the verified payload. Every other handler that touches commits/stacks (e.g. `CheckSuiteHandler`) scopes through `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)`, but `StatusHandler` does not, so a `status` webhook validly signed for repository R2 can mutate a `Shipit::Commit`/`Shipit::Status` belonging to an unrelated stack R1 whenever the two repositories happen to share a commit sha.

### Finding Description
Broken binding: `repository named in verified payload (params.dig('repository','full_name') == R2)` **should equal** `repository owning the Commit row being mutated (Commit#stack.repository)`, but the code never establishes or checks this equality.

Path:
- `WebhooksController#create` parses the JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) .
- `verify_signature` only authenticates that the payload was signed with the `webhook_secret` configured for `repository_owner` (`payload.dig('repository','owner','login')`) via `Shipit.github(organization: repository_owner)` / `GitHubApp#verify_webhook_signature` [2](#0-1) [3](#0-2) . This proves the request came from GitHub for org/repo R2 — it proves nothing about which `Commit` row will be touched.
- `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [4](#0-3) 
This query has no `stack_id`/repository filter at all. Contrast with `CheckSuiteHandler#process`, which correctly scopes through `stacks.where(branch: ...)` before touching commits [5](#0-4) , and with `Handler#stacks`, which is the intended mechanism (`Repository.from_github_repo_name(repository_name)&.stacks`) that `StatusHandler` bypasses entirely [6](#0-5) .
- `create_status_from_github!` unconditionally creates a `Status` row scoped to that commit's own `stack_id`, firing `enable_ci_on_stack`, `schedule_continuous_delivery`, hooks, and CD side effects on R1's stack [7](#0-6) [8](#0-7) .

Exploit flow: Shipit installations that onboard multiple GitHub orgs each get their own `GitHubApp` config/`webhook_secret` (multi-tenant support demonstrated by `secrets_double_github_app.yml` and `Shipit.github(organization:)`) [9](#0-8) [10](#0-9) . An attacker who legitimately owns/pushes to repo R2 in one onboarded org can craft a git commit object byte-for-byte identical (same tree, parent, author/committer, timestamps, message) to a known commit that already exists as a `Shipit::Commit` in a different tenant's stack R1 — git's sha1 is content-addressed, so identical content in R2 yields the identical 40-char sha as the one recorded for R1. GitHub emits a genuine, correctly-signed `status` webhook for R2 containing that sha. `verify_signature` passes (it's real, from GitHub, for R2's own webhook_secret). `StatusHandler#process` then finds and mutates the R1 `Commit` row purely by sha match, with zero relation to R2.

Why guards fail: `verify_signature` authenticates the source org/app, not the target commit's ownership; `drop_unhandled_event` only checks event type; `ExplicitParameters` schema only validates payload shape (`sha`, `state`, etc.), not repository/stack membership; no model validation ties `Status`/`Commit` creation back to `payload['repository']['full_name']`.

### Impact Explanation
A payload authenticated for repository R2 causes a write (`Shipit::Status` creation, `Commit#state` transition, CD scheduling, hook emission, potential auto-deploy triggers via `ProcessMergeRequestsJob`/`enable_ci_on_stack`) against an unrelated tenant's `Shipit::Commit`/`Shipit::Stack` (R1), which the attacker never authenticated for and has no access to. This is a payload-for-one-repository-mutates-another's-stack/commit condition, matching the Critical impact category. It is repeatable against any sha the attacker can reproduce in their own repo, and blast radius spans every tenant/stack sharing the same Shipit deployment.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment hosting stacks for more than one GitHub org/repo, each with independent GitHub App/webhook_secret config; (2) attacker has push access to any repo (R2) onboarded into that Shipit instance's `Shipit.github` config, which is the baseline "unprivileged" capability defined in scope; (3) attacker can reproduce an existing commit's exact byte content in their own repo — feasible for any commit whose full metadata (tree, parents, author/committer name+email+timestamp, message) is known/public, requiring no brute force. No secrets, sessions, or elevated roles are needed. Cost is low and the attack is repeatable at will against any sha of interest across tenants.

### Recommendation
In `StatusHandler#process`, scope the lookup through the verified payload's repository, mirroring `CheckSuiteHandler`/`Handler#stacks`: resolve `stacks` from `Repository.from_github_repo_name(repository_name)` and restrict `commits.where(sha: params.sha)` to that scope before calling `create_status_from_github!`, rejecting/ignoring shas that don't belong to the authenticated repository's stacks.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status payload for repo R2 must not update a commit belonging to a different stack/repo (R1)" do
  request.headers['X-Github-Event'] = 'status'

  r1_commit = shipit_commits(:first) # belongs to stack/repo R1 (e.g. shopify/shipit fixture)
  r1_stack_id = r1_commit.stack_id

  # Payload signed/claiming to originate from an unrelated repository R2
  body = {
    'sha' => r1_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => 'attacker-org/r2-repo', 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  assert_no_difference -> { r1_commit.statuses.count } do
    post :create, body:, as: :json
  end
  # Equality check: repository named in verified payload ('attacker-org/r2-repo')
  # must not equal repository owning the mutated commit (r1_commit.stack.repository.full_name)
  assert_not_equal 'attacker-org/r2-repo', r1_commit.stack.repository.full_name
end
```
Currently, because `StatusHandler#process` filters only by `sha`, this assertion fails (a `Status` row is created for `r1_commit` regardless of the `repository` field), proving the binding is broken.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/status.rb (L18-34)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
    end
```
