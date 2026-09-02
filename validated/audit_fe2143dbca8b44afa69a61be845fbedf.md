Found it. `Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by SHA globally, with no repository/organization scoping at all, while webhook signature verification is scoped to the org derived from the payload's `repository.owner.login`. [1](#0-0) [2](#0-1) 

### Title
Cross-repository commit status forgery via organization/repository binding mismatch in webhook signature verification - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App secret to validate a webhook against using `repository_owner`, a value read directly from the *unverified* JSON body (`params.dig('repository', 'owner', 'login')` or `organization.login`). Once the signature check passes for that org, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which resolves the target `Commit` purely `Commit.where(sha: params.sha)` — with no scoping to the repository or organization that produced the signature. In a Shipit deployment tracking multiple GitHub organizations/repositories, an attacker who legitimately administers one onboarded organization (and therefore knows its `webhook_secret`) can sign an arbitrary payload with that secret while setting `sha` to a commit that belongs to a completely different, unrelated repository tracked by the same Shipit instance.

### Finding Description
The relevant binding is: **the organization that authenticated the webhook signature must equal the organization/repository whose data is written**. This binding is broken:

- `verify_signature` picks `Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that org's `webhook_secret` [3](#0-2) . `repository_owner` comes straight from the same untrusted request body being verified, so it merely proves "the sender knows *some* configured org's secret," not that the secret matches the data being acted on.
- Compare this to `Handler#stacks`, which does correctly scope other handlers to `payload.dig('repository', 'full_name')` [4](#0-3) .
- `StatusHandler`, however, does not go through `stacks`/`repository_name` at all. It resolves the target purely by commit SHA across the *entire* database: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) .

Because SHA-1 commit hashes from real projects can be known/observed publicly (e.g. via any repository's commit history, PRs, or GitHub API), an attacker who is a legitimate admin of Org A (with a working, correctly configured GitHub App/webhook on some repo tracked by this Shipit instance) can send a forged `status` webhook: `X-Github-Event: status`, signature computed with Org A's `webhook_secret`, but `sha` referencing a commit belonging to Org B's repository/stack. `verify_signature` passes because it only checks Org A's secret against the raw body Org A's attacker crafted themselves; `StatusHandler` then writes an arbitrary commit status (`state`, `description`, `target_url`, `context`) onto Org B's commit with no cross-check that the commit's repository matches `repository_owner`.

### Impact Explanation
Commit statuses are used by Shipit as deployability gates (e.g. CI status checks controlling whether a commit can be deployed). Forging a `success` status on an otherwise-failing or unreviewed commit in an unrelated repository can make that commit appear deployable, enabling an unauthorized deploy of a commit that never passed the real repository's checks — this crosses the "unauthorized deploy" impact threshold called out in scope, and is a cross-repository write to state (`Status`) belonging to a repository the attacker's org never authenticated for. This satisfies the "Critical" impact bar (cross-repository writes / unauthorized deploy) since the write is not scoped to the authenticating org at all.

### Likelihood Explanation
Requires only that the attacker control (or have webhook-secret knowledge for) *any* single organization onboarded to the same shared Shipit instance — a low bar for any multi-tenant/multi-org Shipit deployment (the engine explicitly supports configuring `github:` per-organization, see `config/secrets.development.example.yml`) — plus knowledge of a target commit SHA in another tracked repository, which is often public information. No session, API token, or repository write access to the victim repository is needed; only the ability to send an HTTP POST to `/webhooks` with a validly-signed-for-Org-A body.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving objects independent of `stacks`) to the repository identified in the payload, and additionally verify that the resolved `repository_owner`/organization used for signature verification actually owns the repository referenced by the commit/stack being mutated — e.g. join through `Commit -> Stack -> Repository` and reject/ignore statuses whose repository does not match `repository_owner`.

### Proof of Concept
1. Shipit is configured with two orgs, `orgA` (attacker-controlled, webhook secret `secretA`) and `orgB` (victim, tracks `orgB/victim-repo`), both installed on the same Shipit instance.
2. Attacker learns a real commit SHA in `orgB/victim-repo` (e.g. from a public PR).
3. Attacker computes `sha1=` HMAC of a crafted JSON body using `secretA` (their own known webhook secret):
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/some-repo" }
}
```
4. POST to `/webhooks` with `X-Github-Event: status` and the computed `X-Hub-Signature`.
5. `verify_signature` passes (secret matches `orgA`) [6](#0-5) ; `StatusHandler` finds and updates the commit in `orgB/victim-repo` regardless of the `orgA` origin [5](#0-4) .

Note: I was unable to fully trace `commit.create_status_from_github!` and the exact deploy-gating logic that consumes `Status` records within the size limits of what I could search; a Devin session with full repository access could confirm the exact downstream deploy-gating effect of a forged `success` status.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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
