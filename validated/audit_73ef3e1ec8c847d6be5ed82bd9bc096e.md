### Title
Webhook signature verification is keyed by attacker-supplied `repository.owner.login`, letting events be forged for any repository when any onboarded organization has no `webhook_secret` configured - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/org secret to validate the HMAC signature against using a field taken straight out of the unverified JSON body, while every event `Handler` subsequently acts on a *different* field of that same unverified body (`repository.full_name`) to decide which `Stack`/`Repository`/`Commit` to mutate. These two fields are never required to agree, and if the org selected for verification has `webhook_secret` blank/nil, `verify_webhook_signature` short-circuits to `true` for *any* signature (including none), so the whole signature check becomes a no-op for that org while the handler still trusts `repository.full_name` naming an arbitrary other repository/stack.

### Finding Description
The equality that should hold is:

`organization used to verify signature == organization/repository the handlers act upon`

but the code breaks this binding:

1. `verify_signature` picks the app config to check against based on payload-controlled data: [1](#0-0) [2](#0-1) 

2. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no secret is configured for that org: [3](#0-2) 

3. Handlers (e.g. `PushHandler`, `StatusHandler`, `PullRequest::ClosedHandler`) resolve the target repository/stack from a completely different, independently attacker-controlled payload field — `repository.full_name` (or bare `sha`, with no repository binding at all for `StatusHandler`): [4](#0-3) [5](#0-4) [6](#0-5) 

The Shopify-maintained sample secrets configuration itself documents `webhook_secret` as an optional/nilable field, illustrating this is an anticipated deployment shape, not a misconfiguration edge case: [7](#0-6) 

Given a Shipit instance onboarding multiple GitHub organizations (a documented multi-org configuration, as tested in `test/dummy/config/secrets_double_github_app.yml`), if *any one* of those orgs has no `webhook_secret` set, an unauthenticated internet client can:
- Set `repository.owner.login` (or `organization.login`) to the org with no secret, so `verify_signature` resolves `Shipit.github(organization: ...)` to that app and `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header value.
- Set `repository.full_name` (used by `Handler#repository_name`/`#stacks`) to point at a *different* organization's repository that is actually tracked by Shipit and protected by a real secret.
- Craft the rest of the JSON body (`sha`, `state`, `context`, `ref`, `after`, `action`, `pull_request`, etc.) to drive the handler logic for that unrelated repository's stacks/commits.

`StatusHandler` is especially severe because it does not even check `repository.full_name` — it matches purely on `Commit.where(sha: params.sha)` across the whole database, so a forged `status` event with a real commit SHA (easily learned from any public GitHub repo or Shipit UI) can inject arbitrary CI status records for that commit in any stack: [8](#0-7) 

### Impact Explanation
Commit statuses created this way feed directly into deploy-readiness (`Commit#deployable?`/CI checks) and merge-queue logic (`MergeRequest::StatusChecker`, `reject_unless_mergeable!`, `all_status_checks_passed?`), which gate both the "Deploy" button in the UI and the automated merge queue's `merge!` call to GitHub: [9](#0-8) [10](#0-9) 

By forging fake "success" statuses for a commit that never actually passed CI, an unprivileged external attacker can make Shipit believe a commit is deployable/mergeable, leading to an unauthorized deploy or an unauthorized merge to the tracked repository — matching the "unauthorized deploy, rollback, or merge" Critical-impact category. Push events can also be forged to trigger `GithubSyncJob`/`sync_github` against an arbitrary stack chosen purely by the attacker's `repository.full_name` value, decoupled from whichever org's (non-)secret was used to pass verification.

### Likelihood Explanation
Exploitability depends entirely on the deployment having at least one onboarded organization with `webhook_secret` left blank — this is not a hypothetical: the engine's own reference secrets file explicitly ships `webhook_secret: # nil` as example configuration, and multi-org configurations (`Shipit.github(organization: ...)`) are a supported, tested feature (`test/dummy/config/secrets_double_github_app.yml`). No credentials, tokens, or GitHub App keys are required by the attacker; only knowledge of the target org's login name (public) and, for the `status` handler, a target commit SHA (public on GitHub). This is a plausible, unprivileged, network-reachable attack surface (`POST /webhooks`), fully within the engine's own code (`app/controllers`, `app/models/shipit/webhooks`, `lib/shipit/github_app.rb`).

### Recommendation
- Verify the HMAC signature using a secret bound to the actual repository/organization the event payload claims to modify (i.e., resolve via `repository.full_name`'s owner, not a separately-dug `repository.owner.login`/`organization.login`, or cross-check both match), and require the org's own secret for that specific repository.
- Do not allow `verify_webhook_signature` to silently pass (`return true unless webhook_secret`) for organizations with no secret configured when tracked repositories exist; either require every onboarded org to configure a `webhook_secret`, or reject webhooks for orgs without one.
- In `StatusHandler`, verify the commit's `stack.repository` corresponds to the same repository that was authenticated for the webhook delivery, instead of matching status-name-only over `Commit.where(sha:)` globally.

### Proof of Concept
Precondition: Shipit instance configured with two orgs, e.g. `github: { OrgNoSecret: { webhook_secret: nil }, OrgTarget: { webhook_secret: "realsecret" } }`, and a stack tracking `OrgTarget/target-repo` with commit `deadbeefcafebabefeed1234deadbeefcafebabe` pending CI.

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-omitted

{
  "sha": "deadbeefcafebabefeed1234deadbeefcafebabe",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgNoSecret" }, "full_name": "OrgNoSecret/whatever" }
}
```

- `repository_owner` resolves to `OrgNoSecret` → `Shipit.github(organization: "OrgNoSecret")` has `webhook_secret` nil → `verify_webhook_signature` returns `true` unconditionally.
- `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a "success" status on the real `OrgTarget/target-repo` commit, independent of the org used for verification.
- The stack's deploy readiness / merge queue now treats that commit as CI-passing, enabling an unauthorized deploy or merge without ever knowing `OrgTarget`'s real webhook secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
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
    end
  end
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
