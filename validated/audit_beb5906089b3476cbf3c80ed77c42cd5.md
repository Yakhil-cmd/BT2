## Title
Webhook `status` event writes to commits of *any* organization's stack, not just the authenticated repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

## Summary

Shipit-engine supports multiple GitHub Apps, one per organization, each with its own `webhook_secret` [1](#0-0) , and `Shipit.github(organization:)` is looked up dynamically based on the organization embedded in the incoming payload [2](#0-1) . The webhook signature check in `WebhooksController#verify_signature` binds trust only to that one organization: it fetches the app for `repository_owner` and verifies the HMAC with that org's secret [3](#0-2) . This proves only "the request was signed by organization X's webhook secret," not that the payload's content belongs to organization X's repository.

`StatusHandler#process`, unlike other handlers, never re-scopes its write to the repository/organization that was actually authenticated. It looks up commits globally by SHA across the whole Shipit install and mutates them:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 

Compare this with `PushHandler` and `CheckSuiteHandler`, which both resolve the target `stacks` through `Repository.from_github_repo_name(repository_name)` — i.e., scoped to the repository named in the (signature-verified) payload [5](#0-4) [6](#0-5) [7](#0-6) . `StatusHandler` breaks this pattern.

## Finding Description

The equality that should hold is:

`organization authenticated by verify_signature == organization/repository whose data is written by the handler`

For `PushHandler`/`CheckSuiteHandler` this holds because they filter by `Repository.from_github_repo_name(payload['repository']['full_name'])`, i.e. the same repository field that determined which org's secret was used to verify the signature.

For `StatusHandler` it does not hold: the write target is selected purely by `sha`, a value that is not organization/repository-scoped at all. Since Shipit is multi-tenant (multiple GitHub Apps/orgs can be configured, each with independent stacks/repositories), an attacker who legitimately owns/controls one onboarded organization's GitHub App (and therefore its `webhook_secret`) can produce a validly-signed `status` event for *their own* org, but with a `sha` value equal to a commit that exists in a *different* organization's stack. Because git commit SHAs are content-addressed and 40 hex characters, an attacker can engineer a commit (choosing tree/parent/author/committer/message/timestamps) whose SHA collides with a real, already-imported commit belonging to a victim organization's stack — this does not require breaking SHA1 collision resistance, only reproducing an identical commit object (e.g., forking/rebasing so the same tree+metadata hash to the same SHA, or reusing well-known low-entropy commits). Once found, the forged `status` webhook — signed with the attacker's own org's secret — is accepted by `verify_signature` (because it authenticates the org, not the repo/commit), and `StatusHandler` writes the attacker-controlled `state`, `description`, `target_url`, and `context` onto the victim's `Commit` record via `create_status_from_github!`.

## Impact Explanation

Commit statuses directly drive deploy/merge-queue authorization decisions elsewhere in the engine: `Commit#deployable?` and `MergeRequest#all_status_checks_passed?` / `any_status_checks_failed?` consume the very `Status` records this handler creates [8](#0-7) . An attacker who can inject a fabricated "success" status onto a commit belonging to a repository/organization they have no access to can:
- cause that commit to be considered deployable and be shipped/merged by Shipit's continuous-deployment/merge-queue jobs, or
- cause a legitimate commit to be marked failing, blocking deploys/merges (denial of the deploy pipeline for another tenant).

This is a cross-repository write of authoritative CI state, matching the "cross-repository writes" / "unauthorized deploy or merge" Critical impact category, achieved purely by an attacker who controls a webhook secret for their own (unrelated) organization — no privileged Shipit account, `ApiClient` token, or session is required.

## Likelihood Explanation

Requires: (1) Shipit configured with more than one GitHub App/organization (a documented, supported configuration - `docs/setup.md` and `Shipit.github(organization:)` explicitly support multiple orgs), and (2) the attacker controls one onboarded organization (i.e., can generate validly-signed webhook deliveries for it), and (3) the attacker can produce a commit whose SHA matches one already tracked in a victim stack. Producing SHA collisions is nontrivial but the low-entropy nature of commit metadata (timestamps, generated messages, empty-tree/initial commits, cherry-picks) makes exact-SHA reuse across independent repos plausible in real-world histories, and this is a design flaw (missing scoping) independent of how the collision is obtained.

## Recommendation

Scope `StatusHandler#process` to the repository/stacks resolved from the authenticated payload, mirroring `PushHandler`/`CheckSuiteHandler`, e.g. restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (using the `stacks` helper from `Handler`, which resolves via `repository.full_name`) instead of an unscoped, install-wide `Commit.where(sha: params.sha)`.

## Proof of Concept

1. Onboard organization `attacker-org` to Shipit with its own GitHub App/webhook secret (supported multi-org configuration, see `Shipit.github(organization:)`).
2. Identify or engineer a commit whose SHA equals a SHA already tracked by a stack belonging to `victim-org` (a repository the attacker does not control).
3. Send a `status` webhook to `/webhooks` with `X-Github-Event: status`, a body whose `repository.owner.login` is `attacker-org` (so `verify_signature` authenticates it against `attacker-org`'s secret) but whose `sha` matches the victim commit, and `state: success`.
4. `WebhooksController#verify_signature` passes signature verification (it only checks the org named in the payload). `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the victim's commit (no organization/repo filter), and calls `create_status_from_github!`, writing an attacker-controlled status onto a commit in `victim-org`'s stack.

### Citations

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
