### Title
Cross-organization forged CI status leads to unauthorized deploy via webhook signature/target mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook using the GitHub organization derived from `repository.owner.login` (or `organization.login`), selecting a per-organization `webhook_secret` for HMAC verification. However, the code that actually *acts* on the payload — e.g. `StatusHandler#process` — resolves its target purely from attacker-controlled fields (`sha`, and, for other handlers, `repository.full_name` via `Handler#stacks`) that are never cross-checked against the organization whose secret was used to authenticate the request. This is the same class of bug as the reported Gearbox issue: a value that is *acted upon* (`sha` / target repository) is never covered by the check that is supposed to gate the action (the webhook signature, which only binds to an *organization*, not to the specific repository/commit being mutated).

### Finding Description
- `WebhooksController#verify_signature` picks the GitHub App config to verify against using `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . In a multi-tenant Shipit deployment, each GitHub organization has its own App config and `webhook_secret` (see the multi-org example in `config/secrets.development.shopify.yml` and `docs/setup.md`) [2](#0-1) .
- Once the signature is valid for *some* configured organization, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the entire raw JSON body to handlers, with no re-validation that the organization used for signing matches the repository/commit that the handler will mutate [3](#0-2) .
- `StatusHandler#process` looks up commits **globally by SHA** (`Commit.where(sha: params.sha)`), with no repository/organization scoping at all, and writes a CI status taken verbatim from the attacker-supplied payload (`state`, `description`, `context`, `target_url`) [4](#0-3) .
- Other handlers (e.g. `PushHandler`) resolve their target stack via `Handler#stacks`, which uses `payload.dig('repository','full_name')` [5](#0-4)  — a field that is completely independent from the `repository.owner.login`/`organization.login` field used to select the verification secret.

**The broken binding, as an equality:**
`organization authenticated by verify_signature (repository.owner.login / organization.login)` ≠ `repository/commit actually written by the handler (repository.full_name or bare sha lookup)`.

Because these two fields are never checked for consistency, any principal capable of computing a valid HMAC for **any one** configured organization (e.g. a legitimate tenant who owns their own App's `webhook_secret` in a multi-org install) can craft an HTTP POST directly to the shared `/webhooks` endpoint with:
- `repository.owner.login` = their own org (so `verify_signature` picks their own known secret and passes), and
- `sha` (for `status`) or `repository.full_name` (for `push`, etc.) pointing at a completely different organization's stack/commit.

### Impact Explanation
The `status` webhook path is the most severe: an attacker who is a legitimate customer/org-owner in a multi-tenant Shipit instance can forge a `commit_status` event, correctly signed with their own webhook secret, but targeting any known commit SHA belonging to a different organization's stack. Because `Commit.where(sha:)` performs no repository scoping, this injects an arbitrary (e.g. `state: "success"`) CI status onto a victim's commit. Since `ci.require` / `all_status_checks_passed?` and the merge-queue's `StatusChecker` gate deploys and auto-merges purely on these `Status` DB rows [6](#0-5) , this can satisfy required-status checks that were never actually run, enabling an **unauthorized deploy or unauthorized auto-merge** of a commit that should have been blocked by CI — matching the report's Critical "unauthorized deploy/merge" category.

### Likelihood Explanation
Requires the attacker to control (or know) a valid `webhook_secret` for at least one organization configured on the shared Shipit instance — realistic for any legitimate multi-tenant customer of a shared Shipit deployment, and does not require compromising the victim organization, GitHub, or any Shipit session/API token. The victim's commit SHA is often discoverable (public repos, PR pages, GitHub API). This is a moderate-likelihood, high-impact issue in any deployment supporting multiple GitHub organizations behind one Shipit instance.

### Recommendation
Bind the verified organization to the resource being mutated: after `verify_signature` succeeds, re-derive `repository.full_name` / commit ownership strictly from `repository_owner`, and reject (or ignore) events where the repository/commit referenced in the payload does not belong to the same organization that was cryptographically authenticated. In particular, `StatusHandler` should scope `Commit.where(sha:)` to commits whose stack's repository owner matches `repository_owner`, and `Handler#stacks`/`repository_name` should validate that the derived owner matches the authenticated organization before dispatching to any handler.

### Proof of Concept
1. Attacker administers `attacker-org`, which is configured in Shipit's multi-org `github:` settings with a known `webhook_secret_A`.
2. Attacker identifies a commit SHA `deadbeef...` on `victim-org/victim-repo`, tracked as a stack in the same shared Shipit instance, whose required CI check (`ci/circleci`) is currently failing or missing.
3. Attacker computes `sha1=HMAC-SHA1(webhook_secret_A, body)` over a crafted JSON body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
4. POST to `/webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
5. `verify_signature` resolves `repository_owner = "attacker-org"`, verifies successfully against `webhook_secret_A`, and passes.
6. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")`, finds the victim's commit (unscoped by org), and writes a fabricated `success` status for `ci/circleci`.
7. If `victim-org/victim-repo`'s stack has continuous delivery enabled or a pending merge request, the fabricated status satisfies `ci.require`, resulting in an unauthorized deploy or merge.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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
