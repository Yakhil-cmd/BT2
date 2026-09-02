This confirms the vulnerability. The `StatusHandler` at [1](#0-0)  looks up commits globally by `sha` alone (`Commit.where(sha: params.sha)`) — with no scoping to the repository/organization whose secret verified the request — and directly persists attacker-supplied `state`, `description`, `target_url`, and `context` fields onto that commit's status via `commit.create_status_from_github!(params)`. This can flip a commit's CI status to `success`, satisfying `ci.require` checks and unblocking `deployment_checks_passed?`/deploy gating.

### Title
Cross-organization webhook forgery allows unauthorized commit status injection and CI-check bypass — (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using an attacker-controlled JSON field (`repository.owner.login`, or `organization.login` as fallback) rather than any value bound to the actual GitHub delivery. [2](#0-1)  Handlers, however, act on a *different* attacker-controlled field, `repository.full_name`, to resolve which `Repository`/`Stack`/`Commit` the payload affects. [3](#0-2)  Because these two fields are never checked for consistency, and `StatusHandler` further resolves target commits engine-wide by `sha` with no repository scoping at all, a party who legitimately administers one Shipit-configured GitHub organization (and therefore knows/controls that organization's `webhook_secret`) can forge a signature valid for their own org while embedding an arbitrary `repository.full_name`/`sha` belonging to a **different** organization's stack. [4](#0-3) 

### Finding Description
The binding that should hold is: `organization whose secret authenticated the request == organization whose repository/commit is written`. In `verify_signature`:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

`repository_owner` is read straight out of the unauthenticated (pre-verification) JSON body, and it selects *which* org's `webhook_secret` is used to check the HMAC (see `GitHubApp#verify_webhook_signature`, `lib/shipit/github_app.rb:76-83`). Once the signature validates against that org's own secret, the controller dispatches the *entire* body — including any other, unrelated `repository.full_name`/`sha` fields — to handlers.

`Handler#repository_name` (used by most handlers to scope processing) reads a separate field:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

Nothing enforces that `repository.full_name` is owned by `repository.owner.login`/`organization.login`. `StatusHandler` is worse: it doesn't even use `repository_name`/`stacks` scoping, but resolves target `Commit` rows globally by SHA:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Any commit in the whole Shipit instance sharing that SHA (e.g. same open-source dependency commit, or a guessed/observed SHA from a public repo) gets a forged CI status attached, regardless of which organization's secret validated the request.

This is the direct analog of the referenced report's root cause: a value that is authorized/validated at one binding point (decimals assumed but never checked; here, "organization" implied by the signature check) is silently different from the value that actually drives the effectful computation (actual token decimals; here, the actual repository/commit being written).

### Impact Explanation
An attacker who operates any organization onboarded to a shared multi-tenant Shipit deployment (knows that org's own `webhook_secret`, which they configure/receive when the GitHub App is installed) can sign arbitrary payloads and inject fabricated `success` commit statuses for commits belonging to a different organization's stacks. Since `Status#enable_ci_on_stack` and `commit.create_status_from_github!` feed directly into `ci.require`/`Stack#deployment_checks_passed?` gating used to permit deploys, this can be used to satisfy CI requirements that were never actually met, leading to an **unauthorized deploy** — matching the Critical impact bucket in scope ("an unauthorized deploy, rollback or merge"). It also lets an attacker pollute another organization's commit-status history/UI.

### Likelihood Explanation
This requires only that the attacker administers/controls one legitimate org connected to the same Shipit instance (a normal, low-privilege scenario in a multi-tenant deployment as shown by `config/secrets.development.shopify.yml`, which lists multiple orgs each with independent `webhook_secret`s) — no `ApiClient` token, no GitHub write access to the victim repo, and no compromise of the victim org's secret is needed. The only additional requirement is guessing/observing a target SHA already tracked by Shipit (trivial for public repos, or a common dependency commit), making this practically exploitable wherever the engine hosts more than one organization.

### Recommendation
Bind repository resolution to the same identity used for signature verification: after `verify_signature` succeeds for organization `O`, all handlers (and especially `StatusHandler`) must additionally verify that the resolved `Repository`'s owner/organization equals `O`, rejecting or ignoring payloads where `repository.full_name`'s owner doesn't match `repository.owner.login`/`organization.login`. `StatusHandler#process` should scope `Commit` lookups through `stacks` (i.e., through `Repository.from_github_repo_name(repository_name)`) rather than a bare `Commit.where(sha:)`, so no cross-organization commit can ever receive a status derived from another org's signed webhook.

### Proof of Concept
1. Organization `victim` has a Shipit stack tracking commit SHA `abc123`, currently lacking a passing `ci/travis` status (so deploys are blocked by `ci.require`).
2. Attacker controls organization `attacker`, configured in Shipit with its own known `webhook_secret_attacker`.
3. Attacker computes `sha256=HMAC(webhook_secret_attacker, body)` over a crafted JSON body:
   ```json
   {
     "sha": "abc123",
     "state": "success",
     "context": "ci/travis",
     "description": "forged",
     "repository": { "owner": { "login": "attacker" }, "full_name": "victim/some-repo" }
   }
   ```
4. POST to `/webhooks` with `X-Github-Event: status` and the computed `X-Hub-Signature`.
5. `verify_signature` resolves `repository_owner` = `"attacker"`, fetches `Shipit.github(organization: "attacker")`, and the HMAC checks out — request is accepted.
6. `StatusHandler#process` runs `Commit.where(sha: "abc123")`, finds the victim's commit (unscoped by org), and calls `commit.create_status_from_github!(params)`, creating a `success` status for `ci/travis` on the victim's commit — satisfying `ci.require` and enabling deploy, despite the attacker never having access to `victim`'s repository or webhook secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
