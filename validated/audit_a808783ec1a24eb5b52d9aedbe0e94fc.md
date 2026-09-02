### Title
`provision?` operator-precedence bug bypasses `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` repositories - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` intends the binding `review_stacks_enabled == true AND (allow_all? OR (allow_with_label? AND has_label?) OR (prevent_with_label? AND !has_label?))`, but Ruby's `&&`/`||` precedence makes `review_stacks_enabled` a conjunct of only the first disjunct. For repositories configured with `provisioning_behavior = :allow_with_label` or `:prevent_with_label`, `provision?` returns `true` even when `review_stacks_enabled` is `false`, allowing `ReviewStackAdapter#find_or_create!` to run and provision a review stack that should never have been created.

### Finding Description
The broken binding, as an explicit equality:
- Intended: `provision? == (repository.review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)))`
- Actual: `provision? == (repository.review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

The code is exactly: [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, `review_stacks_enabled` is grouped only with `provisioning_behavior_allow_all?`; the other two disjuncts (`allow_with_label?`/`prevent_with_label?`) are evaluated independently of `review_stacks_enabled`.

`process` gates on `respond_to_pull_request_opened?`, which calls `provision?` directly: [2](#0-1) 

`repository` is resolved purely from the attacker-controlled `params.repository.full_name` in the webhook payload with no additional authorization check beyond signature verification: [3](#0-2) 

Exploit flow: for any repository already configured by its owner/maintainer with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) but `review_stacks_enabled: false` — i.e., review stacks temporarily disabled while the label-gating policy remains configured — an unprivileged contributor who can open a pull request and apply/omit a label on their own PR can cause `provision?` to evaluate `true` and trigger `ReviewStackAdapter#find_or_create!`, provisioning a review stack (and its associated task/deploy machinery) despite the repository having explicitly disabled review stacks.

Existing guards do not prevent this divergence: `verify_signature` in `WebhooksController` only authenticates that the payload came from the real GitHub webhook for that org/repo — it says nothing about whether review stacks are enabled — and `drop_unhandled_event`/`ExplicitParameters` schema checks only validate payload shape, not the `review_stacks_enabled` gate. [4](#0-3) 

### Impact Explanation
This is a logic/authorization bug: it causes creation of a `ReviewStack` (and downstream deploy/task infrastructure) for a repository whose operator explicitly turned `review_stacks_enabled` off, purely because a leftover `provisioning_behavior` value of `allow_with_label`/`prevent_with_label` remains set. It is repeatable on any repository matching that specific configuration combination (`review_stacks_enabled: false` + `provisioning_behavior: allow_with_label` or `prevent_with_label`) and is triggered by an ordinary PR-open plus label action from any contributor to that repository — no elevated privilege is required beyond being able to open a PR on/against the target repo. The blast radius is scoped to repositories in that specific misconfiguration state; it is not a cross-tenant forgery (attacker still needs a real, signed GitHub webhook for the targeted repo), so it does not by itself grant control over unrelated repositories' stacks.

### Likelihood Explanation
Preconditions are narrow but plausible: the affected repository must have `review_stacks_enabled == false` while `provisioning_behavior` is still set to `:allow_with_label` or `:prevent_with_label` (a state an operator could reach by toggling `review_stacks_enabled` off without also resetting `provisioning_behavior`, per `RepositoriesController`/settings UI). Given that state, the attacker cost is trivial: open a PR (and add/omit a label), which is normal, unprivileged GitHub activity, and GitHub's own webhook delivery (correctly signed) drives the vulnerable code path. It is fully repeatable for every PR opened while the repository remains in that configuration.

### Recommendation
Fix operator precedence in `provision?` by explicitly grouping `review_stacks_enabled` with the entire disjunction, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (existing suite location), add a minitest case:
1. Build/stub a `Shipit::Repository` (or mock) with `review_stacks_enabled` returning `false`, `provisioning_behavior` set to `:allow_with_label`, and `provisioning_label_name` set to `"deploy-preview"`.
2. Construct `params` for an `OpenedHandler` where `pull_request.labels` includes `{"name" => "deploy-preview"}`.
3. Stub `Shipit::Repository.from_github_repo_name` to return this repository.
4. Instantiate `OpenedHandler.new(params)` and call `handler.send(:provision?)`.
5. Assert equality mismatch demonstrating the bug:
   - Expected (per intended binding): `repository.review_stacks_enabled && repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label? == false` (since `review_stacks_enabled` is `false`).
   - Actual: `handler.send(:provision?) == true`.
6. Assert `assert handler.send(:provision?)` succeeds while `assert_equal false, repository.review_stacks_enabled` also holds, proving `review_stacks_enabled` was never a binding conjunct on the `allow_with_label` branch.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-63)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
