### Title
Webhook signature verified against `repository.owner.login`/`organization.login`, but write scope of `push`/`check_suite`/`status` handlers keyed on unbound `repository.full_name` or a completely unscoped commit `sha` — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp`/`webhook_secret` to validate the inbound HMAC using `repository_owner`, derived from `payload.dig('repository','owner','login')` (falling back to `payload.dig('organization','login')`). The event handlers that actually mutate state, however, resolve the target `Repository`/`Stack` using a *different* field of the same payload — `payload.dig('repository','full_name')` — and in `StatusHandler` do not scope by repository at all, matching purely on `Commit.sha` globally. This breaks the equality "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) does: [1](#0-0) [2](#0-1) 

The GitHub App/secret used for verification is chosen only by `repository_owner`. Nothing binds the verified organization to the specific `repository.full_name` that will subsequently be acted upon.

The base `Handler` class, used by `PushHandler` and `CheckSuiteHandler`, resolves the target stacks purely from `payload.dig('repository', 'full_name')`: [3](#0-2) 

`Repository.from_github_repo_name` splits this attacker-supplied string on `/` to find owner/name independently of the signature-verifying `repository.owner.login`: [4](#0-3) 

`StatusHandler` is worse: it never checks repository/stack scope at all, matching only by the raw `sha` across the entire `Commit` table and writing attacker-controlled state (`state`, `description`, `target_url`, `context`, `created_at`) directly: [5](#0-4) [6](#0-5) 

This equals the report's bug class: the signature/voting check validates one identity (`txId`/org) while the mutated data (account/repository) is taken from an unverified, independently-controlled field of the same payload.

### Impact Explanation
An attacker who legitimately administers **their own** GitHub organization/App installation on a multi-tenant Shipit instance (a normal, unprivileged tenant, not a Shipit user account, ApiClient, or GitHub App private key holder) knows their own org's `webhook_secret` (they configured it when installing their own GitHub App per `docs/setup.md`/`config/secrets.*.yml` multi-org format). They can self-sign an arbitrary JSON body with that known secret and POST it to `/webhooks`:
- Set `repository.owner.login`/`organization.login` = their own org (passes `verify_signature`).
- Set `repository.full_name` = a victim org/repo tracked by the same Shipit instance, or (for `status`) simply guess/know a public commit `sha` belonging to a victim stack.

Consequences:
- `StatusHandler`: forge a passing CI status (`state: success`) for any commit sha in any tracked stack, satisfying `Commit#deployable?`/`require_ci` (`app/models/shipit/commit.rb:227-229`) and enabling an **unauthorized deploy** of a commit that never actually passed CI, or triggering `schedule_continuous_delivery` for stacks with `continuous_deployment?` enabled (`app/models/shipit/commit.rb:281-287`) — an unauthorized ship without any repository write access or GitHub credentials on the victim repo.
- `PushHandler`/`CheckSuiteHandler`: trigger `sync_github`/check-run refresh actions against a victim stack the attacker does not own, a cross-tenant action outside their authorization boundary.

This matches the listed High/Critical impacts: unauthorized deploy and cross-repository writes, achieved purely by crossing the organization/repository authorization boundary — no ApiClient token, GitHub App private key, or Shipit session required.

### Likelihood Explanation
Requires only: (1) the Shipit instance configured for multiple GitHub organizations (documented, supported feature — see `test/dummy/config/secrets_double_github_app.yml`), and (2) the attacker to be the legitimate installer/admin of one of those orgs' GitHub Apps (an unprivileged position relative to other tenants' stacks). No interaction with the victim org, no credential theft, and no exploitation of TLS/webhook_secret leakage is needed — the attacker uses their *own* valid secret to sign a payload referencing someone else's repository/commit.

### Recommendation
Bind the verified identity to the acted-upon resource:
- In `WebhooksController#verify_signature`, additionally assert that the `repository.owner.login` (or `organization.login`) used to select the verifying `GitHubApp` matches the owner segment of `repository.full_name`; reject the request otherwise.
- In `Handler#stacks`, look up the target `Repository` and re-derive/compare its `owner` against the same organization value used for signature verification instead of trusting `full_name` alone.
- In `StatusHandler`, scope `Commit.where(sha:)` by the repository resolved from the verified organization (i.e., restrict to `stacks` from `Handler`), rather than matching `sha` globally.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` (attacker-controlled, webhook_secret known to attacker) and `OrgB` (victim), both installed and each tracking a `Stack`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim commit sha from OrgB/repo, known/public>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/attacker-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` using the attacker's own known `webhook_secret` for `OrgA`.
4. POST to `/webhooks` with header `X-Github-Event: status`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates successfully.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's OrgB commit — and calls `create_status_from_github!`, writing a forged `success` status onto it, independent of `OrgA` having any relationship to that commit/stack.
6. If OrgB's stack requires CI (`require_ci`) or has continuous deployment enabled, this forged status can make the commit `deployable?` and trigger deploy/merge automation without ever touching OrgB's real GitHub repository or credentials.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```
