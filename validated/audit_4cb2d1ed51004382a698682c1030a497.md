This confirms `CheckSuiteHandler` correctly scopes lookups through `stacks` (repository-derived), at [1](#0-0) , while `StatusHandler` does not.

### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook by matching the SHA globally across *all* stacks/repositories in the Shipit instance, rather than scoping the lookup to the repository the webhook signature was verified against. This breaks the binding between "the organization/repository whose webhook credentials authenticated the request" and "the repository whose commit state gets mutated."

### Finding Description
The webhook signature is verified per-organization in `WebhooksController#verify_signature`, which selects which GitHub App/secret to check against using `repository_owner`, itself taken directly from the untrusted payload (`params.dig('repository', 'owner', 'login')`), at [2](#0-1) . In a multi-organization deployment (`docs/setup.md` describes this as a supported configuration, and `webhook_secret` is explicitly optional/nilable per org), an attacker who operates or controls a GitHub App installation on *any one* configured organization — especially one where `webhook_secret` is left blank, in which case `verify_webhook_signature` returns `true` unconditionally — can produce a webhook payload that GitHub-signature-verifies successfully for that org, at [3](#0-2) .

Once signature verification passes, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, whose `process` method does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
at [4](#0-3) . This lookup is **not** scoped by the `stacks`/`Repository.from_github_repo_name` helper that the base `Handler` class provides and that other handlers (e.g. `CheckSuiteHandler`) correctly use, at [5](#0-4)  and [1](#0-0) . As a result, `Commit.where(sha:)` matches any commit row in the entire database sharing that SHA, regardless of which repository/organization it belongs to — this is realistic for forked repositories or shared history sharing initial commit SHAs across orgs configured on the same Shipit instance.

The binding broken: **organization that authenticated the webhook signature ≠ repository whose commit record is written**. The payload's `repository` field is used only to pick which secret verifies the signature; it is never checked against which `Commit`/`Stack` actually gets mutated.

### Impact Explanation
`Commit#create_status_from_github!` calls `Status.replicate_from_github!`, which creates a `Status` row carrying attacker-controlled `state`, `description`, `context`, and `target_url` at [6](#0-5) . Creating a `Status` triggers `enable_ci_on_stack` (enabling CI gating for a stack the attacker doesn't own) and `schedule_continuous_delivery`, at [7](#0-6) , which affects a commit's deployable/mergeable state (`deployable_status` computed in `Commit`). Forging a `success` status on another organization's commit can make that commit appear deployable or satisfy merge-queue CI requirements, contributing to an **unauthorized deploy or merge** on a repository/organization the attacker does not control — meeting the required "Critical/High" impact bar (unauthorized deploy/merge via cross-repository writes).

### Likelihood Explanation
Exploitability requires: (1) a multi-organization Shipit deployment (explicitly documented and supported), (2) the attacker controlling, or being able to trigger, a signed/legitimately-verifiable webhook for *some* organization on that instance (their own org, or one with no `webhook_secret` configured), and (3) a SHA collision or shared commit history between the attacker's org and the victim org/stack (common for public forks). This is a real but non-trivial precondition set — moderate likelihood, concentrated in shared/multi-tenant Shipit instances.

### Recommendation
Scope `StatusHandler#process` through the same repository-derived `stacks` association the base `Handler` and other handlers use, e.g. restrict the lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalent join), instead of the global `Commit.where(sha:)`. Additionally, consider validating that `repository.full_name`'s owner segment matches the organization whose webhook secret verified the request, to prevent any handler from acting cross-organization even if a future handler introduces a similar unscoped lookup.

### Proof of Concept
1. Operate/control a GitHub org "AttackerOrg" configured in the Shipit instance's multi-org `github:` secrets with `webhook_secret` left blank (or use one you legitimately know).
2. Identify a commit SHA present in a victim organization's tracked stack (e.g., shared initial commit from a public fork, or a well-known SHA the attacker can also produce in their own repo history).
3. Send a forged `status` event to `/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/attacker",
  "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "AttackerOrg/some-repo" }
}
```
4. `verify_signature` resolves `repository_owner` = "AttackerOrg" and passes (blank secret / attacker-known secret).
5. `StatusHandler#process` executes `Commit.where(sha: "<victim commit sha>")`, matching the victim's commit row regardless of `repository.full_name`, and creates a forged `success` `Status` on it — enabling CI/deploy/merge eligibility on a repository the attacker never authenticated against.

### Citations

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/status.rb (L18-20)
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
