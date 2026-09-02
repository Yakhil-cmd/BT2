### Title
Cross-organization commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook by resolving a `GitHubApp` from the *organization* named in the payload (`repository.owner.login` / `organization.login`) and checking the signature against that organization's own `webhook_secret`. In a multi-tenant Shipit deployment (multiple orgs configured under `Shipit.github`, as exercised by `test/dummy/config/secrets_double_github_app.yml`), this only proves "this payload was signed by *some* configured organization's secret" — it proves nothing about which repository the payload's other fields describe. `Shipit::Webhooks::Handlers::StatusHandler#process` then acts on `params.sha` by querying `Commit.where(sha: params.sha)` with no repository/organization scoping at all, unlike every other handler which resolves `stacks`/`repository` via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The binding that should hold is:

`organization whose webhook_secret authenticated the request == organization that owns the repository/commit the handler mutates`

`Shipit.github(organization: repository_owner)` picks the `GitHubApp` (and therefore the HMAC secret) purely from `params.dig('repository', 'owner', 'login')` (or `organization.login`), a field the sender fully controls inside the same JSON body being signed: [4](#0-3) 

`verify_webhook_signature` only proves the payload bytes were signed with *that organization's* secret — it says nothing about the truthfulness of any other field in the payload, including `sha`: [5](#0-4) 

Every other webhook handler re-derives the acted-upon repository from the payload and scopes queries to it, e.g. `Handler#stacks` uses `Repository.from_github_repo_name(repository_name)`: [3](#0-2) 

`StatusHandler`, however, breaks this pattern — it never touches `repository_name`/`stacks`, and instead performs a bare, global lookup of any `Commit` row matching the attacker-supplied `sha`: [6](#0-5) 

Because Shipit supports multiple independently configured GitHub organizations under one instance (`Shipit.github_app_config`, demonstrated by the dummy `secrets_double_github_app.yml` fixture with `OrgOne`/`OrgTwo`), an attacker who legitimately controls one configured organization's webhook secret (they created the GitHub App/webhook for their own org and know its secret) can:

1. Construct a `status` event JSON body where `repository.owner.login` (or `organization.login`) = their own org, so `verify_signature` resolves and validates against their own known secret.
2. Set `sha` to the SHA of a commit that belongs to a completely different, victim organization's repository/stack tracked by the same Shipit instance.
3. Sign the whole body with their own secret and POST it to `/webhooks`.

`verify_signature` passes (correct secret for the org named in the payload), and `StatusHandler#process` finds the victim commit purely `by sha`, ignoring which org "authenticated" the request, and calls `commit.create_status_from_github!(params)` with attacker-chosen `state`, `context`, `description`, `target_url`, `created_at`. [7](#0-6) 

### Impact Explanation
Commit statuses drive Shipit's deployability checks (`ci.require`, `ci.blocking` in `shipit.yml`, evaluated via `deploy_spec.rb`/`stack.rb`/`status/common.rb`). By forging a passing status (e.g. `context: "ci/circleci", state: "success"`) for an arbitrary victim commit SHA that the attacker does not control and has no access to, an attacker in one tenant organization can make an unreviewed/unbuilt commit in a *different* organization's repository appear CI-green in Shipit, enabling that commit to be merged via the merge queue or deployed through Shipit — an unauthorized deploy/merge, which is explicitly listed as a Critical-severity outcome for this analysis.

### Likelihood Explanation
This requires only: (a) the target Shipit instance to be configured for more than one GitHub organization (a supported, documented configuration — see `secrets_double_github_app.yml` and `Shipit.github_app_config`), and (b) the attacker to be a legitimate admin/owner of their own (unprivileged w.r.t. the victim) tenant organization, who by definition knows their own webhook secret since they configure it. No access to the victim's org, repository, or Shipit account is required — the only crafted field is `sha`, which is trivially guessable/obtainable from public commit history or PR metadata of the victim repo. This is a straightforward, deterministic exploitation of a missing authorization scope check, not a race condition or edge case.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository named in the payload (mirroring `Handler#stacks`/`repository_name`), e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or join through `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, and require that `repository.owner.login` matches the organization that authenticated the webhook. More generally, audit all webhook handlers to ensure every one enforces `organization-authenticated == organization-acted-upon` rather than trusting `repository_owner` and the payload's data fields independently.

### Proof of Concept
1. Configure Shipit with two organizations, `victim-org` (has stack tracking `victim-org/app`, commit `abc123...` present) and `attacker-org` (attacker's own tenant, webhook secret known to attacker) — matching the supported multi-org config shown in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts:
```json
{
  "sha": "abc123...(victim commit)",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker's own secret.
5. `StatusHandler#process` executes `Commit.where(sha: "abc123...")` — matching the victim's commit — and calls `create_status_from_github!`, marking the victim's commit as CI-passing in `victim-org/app`, regardless of the attacker having no relationship to that org/repo.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
