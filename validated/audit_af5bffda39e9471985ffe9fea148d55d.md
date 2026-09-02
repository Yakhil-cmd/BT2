### Title
Cross-stack CI status forgery via organization/repository binding break in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to validate an inbound webhook based on `repository.owner.login` (or `organization.login`) pulled from the *unverified* JSON body, but the `status` event handler that then acts on that body never checks that the same repository owns the commit it mutates. `StatusHandler#process` looks up commits globally by `sha` across every stack in the Shipit instance and writes a `Status` row (and fires deploy-gating hooks) for whichever commit matches, with no scoping to the organization/repository whose signature was actually validated.

### Finding Description
`WebhooksController#verify_signature` resolves the authenticating GitHub App like this: [1](#0-0) 
and derives the organization purely from attacker-controlled JSON, prior to any cryptographic check: [2](#0-1) 

Once `verified` is true, the raw payload is dispatched unmodified to every registered handler for the event: [3](#0-2) 

For the `status` event, the only handler is `StatusHandler`, registered in the default handler table: [4](#0-3) 

Crucially, `StatusHandler#process` resolves the target purely by commit SHA, with **no repository/stack scoping at all** — unlike the base `Handler` class which offers a `repository_name`/`stacks` scoping helper that other handlers (e.g. `PushHandler`, pull-request handlers) explicitly use: [5](#0-4) [6](#0-5) 

This breaks the binding: `organization authenticated (via repository_owner → github_app secret)` ≠ `repository/commit actually written (Commit.where(sha:))`. Concretely:

- Before the attacker's request: commit `X` in `Stack A` (owned by `Org A`, which has a `webhook_secret` configured) has no successful CI status; commit checks gate deploy eligibility.
- The attacker controls (or is a legitimate collaborator with webhook-triggering access to) a repository in `Org B`, and `Org B` in the same Shipit installation is configured *without* a `webhook_secret` (an operator choice supported by `GitHubApp#initialize`/`verify_webhook_signature`): [7](#0-6) [8](#0-7) 
  Because `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank, any payload claiming `repository.owner.login = "Org B"` (or `organization.login = "Org B"`) passes signature verification with **no cryptographic proof of anything**.
- The attacker then sets `sha` in that same payload to the SHA of a commit belonging to `Stack A` under `Org A` — a repository/org the attacker has no relationship to and no secret for.
- `StatusHandler` does not check `repository.full_name` at all; it finds the commit purely by SHA (`Commit.where(sha: params.sha)`) across the whole install and calls `commit.create_status_from_github!(params)`, creating a `success` `Status` row for it.
- This status feeds `Commit#deployable?` and downstream deploy-gating logic: [9](#0-8) 
  and is used to decide `next_expected_commit_to_deploy` / continuous-deployment eligibility: [10](#0-9) 

After the attacker's request: the attacker-forged webhook (verified against `Org B`'s absent-secret configuration) has flipped a commit in `Stack A`/`Org A` to `success`, which the deploy pipeline treats as CI-approved, satisfying `deployable?` and potentially unblocking an automatic or one-click deploy of that commit — despite the attacker having no relationship, credentials, or authorization tied to `Org A`, its repository, or its `webhook_secret`.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary. A CI status is a deploy gate (`Commit#deployable?`, `Stack#next_expected_commit_to_deploy`, continuous deployment eligibility); forging it for an arbitrary commit in an arbitrary, unrelated stack can lead to an **unauthorized deploy** of a commit that never actually passed CI — one of the explicitly listed Critical/High impacts (unauthorized deploy).

### Likelihood Explanation
Exploitability is conditioned on at least one organization/GitHub App configured in the multi-org `Shipit.github` setup lacking a `webhook_secret` (a supported, non-default but plausible operational configuration per `GitHubApp#initialize`), which then allows the attacker to bypass HMAC verification entirely for that alias, while still targeting any other stack's commit by SHA since `StatusHandler` performs no per-repository scoping. Commit SHAs are not secret (visible via GitHub, PRs, CI systems, etc.), making the SHA guess practical.

### Recommendation
Scope `StatusHandler` (and any other handler that currently trusts payload fields globally) to the repository identified in the *same signed payload*, mirroring the pattern used in `Handler#stacks`/`repository_name`, e.g. restrict the `Commit.where(sha:)` lookup to commits belonging to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. Additionally, consider making `webhook_secret` mandatory for every configured GitHub App/organization so that `verify_webhook_signature` can never silently short-circuit to `true`.

### Proof of Concept
1. Configure Shipit with two orgs: `OrgA` (has `webhook_secret` set, owns `Stack A` and commit `X` with SHA `abcd123`) and `OrgB` (no `webhook_secret` configured).
2. Send `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "abcd123",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgB" } }
}
```
   with any (or missing) `X-Hub-Signature` header.
3. `repository_owner` resolves to `OrgB`; `Shipit.github(organization: "OrgB").verify_webhook_signature` returns `true` unconditionally because `OrgB` has no `webhook_secret`.
4. `StatusHandler#process` executes `Commit.where(sha: "abcd123")` — matching commit `X` in `Stack A`/`OrgA` — and creates a `success` `Status` on it via `commit.create_status_from_github!`, without ever checking that the payload's authenticating org matches `Stack A`'s owning org.
5. Verify `Stack A`'s commit `X` now reports `deployable?` as `true` due to the forged status, despite no legitimate CI ever running and no credential belonging to `OrgA` being used.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/stack.rb (L332-342)
```ruby
    def next_expected_commit_to_deploy(commits: nil)
      commits ||= undeployed_commits do |scope|
        scope.preload(:statuses, :check_runs)
      end

      commits_to_deploy = commits.reject(&:active?)
      if maximum_commits_per_deploy
        commits_to_deploy = commits_to_deploy.reverse.slice(0, maximum_commits_per_deploy).reverse
      end
      commits_to_deploy.find(&:deployable?)
    end
```
