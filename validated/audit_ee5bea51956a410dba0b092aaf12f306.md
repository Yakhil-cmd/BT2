### Title
Cross-organization commit-status forgery via unscoped `sha` lookup in `StatusHandler` — organization that authenticated ≠ stack whose commit-status is written - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` picks which GitHub App/organization secret to validate the inbound webhook's HMAC against using a field taken from the request body itself (`repository.owner.login` or `organization.login`), not from anything cryptographically bound to the event being processed. `StatusHandler`, which handles the `status` event, then looks up the target commit purely by `params.sha` across the *entire installation*, with no check that the commit's repository/stack belongs to the organization whose secret verified the signature. This breaks the intended binding "organization that authenticated == stack that gets written to."

### Finding Description
`WebhooksController#verify_signature` derives the verifying organization from the untrusted payload before any cryptographic check has meaningfully scoped it to a specific repository: [1](#0-0) [2](#0-1) 

Because `Shipit.github(organization:)` resolves a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per organization key in `secrets.github`, this is only secure if the org named in the payload also constrains what the handler is allowed to act on: [3](#0-2) [4](#0-3) 

`StatusHandler`, however, does not require or check any repository/organization field at all in its schema, and resolves the target commit by `sha` alone, across every stack in the installation: [5](#0-4) 

The write path (`Commit#create_status_from_github!` → `add_status`) then attaches the status to that commit's actual owning stack (`stack_id`), whatever stack that happens to be — the code never checks that this stack belongs to the organization whose webhook secret validated the request signature.

In a Shipit instance configured for several GitHub organizations (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `Shipit.github_app_config`), an attacker who administers *their own* onboarded organization (Org A) knows Org A's `webhook_secret` (or otherwise controls a channel to legitimately produce a validly-signed `status` webhook for Org A, e.g. by triggering a real CI status update on their own public/private repo under Org A). They can set `repository.owner.login`/`organization.login` to `"OrgA"` so the correct (their own) secret verifies the HMAC, while independently setting `sha` to the commit SHA of a target commit belonging to an unrelated stack/repository under a completely different organization (Org B), plus `state: "success"` and a `context` matching a required CI check name for that victim stack. Git commit SHAs of public repositories are publicly observable, so no access to Org B is required.

### Impact Explanation
`StatusHandler` writes a forged `success` (or any) commit status for a commit belonging to an unrelated stack that the attacker has no authorization over. This status feeds directly into merge and deploy gating logic:
- `MergeRequest#reject_unless_mergeable!` uses `StatusChecker`/`any_status_checks_failed?`/`any_status_checks_missing?` (built from the commit's statuses) to decide whether to auto-merge a pull request via `MergeRequest#merge!`, which calls the GitHub API to merge.
- `Commit#deployable?` gates whether a commit can be deployed based on its status state.

A forged, unscoped commit status therefore lets an attacker who only controls an unrelated organization on the same shared Shipit instance influence the auto-merge/deploy readiness of a completely different organization's repository — a cross-repository/cross-organization write, and potentially an unauthorized merge or deploy, without ever holding a Shipit session, API token, or the victim org's `webhook_secret`.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with multiple GitHub organizations sharing one instance (an explicitly documented, supported setup), (2) the attacker to control one of those organizations well enough to produce a validly HMAC-signed `status` event (they know/administer that org's own secret or can trigger a genuine GitHub-originated status event on their own repo), and (3) knowledge of a target commit SHA in the victim stack (trivial for public repos, or any repo the attacker has read access to). No exploitation of TLS, no privileged Shipit account, and no leaked secrets belonging to the victim organization are needed — only the binding between "who signed" and "what gets written" is broken.

### Recommendation
Scope every webhook handler's writes to the organization/repository that was actually verified: `StatusHandler` (and any handler acting on payload-provided identifiers) must require and validate `repository.full_name`/`repository.owner.login`, resolve the target `Stack`/`Repository` through that verified identity, and constrain the `Commit.where(sha: ...)` lookup to `stack.commits` (or `repository.stacks.commits`) rather than the entire `Commit` table. The organization used to select the verifying secret in `WebhooksController#verify_signature` must be the same organization that the handler is permitted to write to — this equality should be enforced structurally (e.g., by passing the verified organization into `Webhooks.for_event(event).each { |handler| handler.call(params, verified_organization:) }` and having handlers reject payloads whose `repository.owner.login` differs from `verified_organization`).

### Proof of Concept
1. Configure a Shipit instance with two organizations, `orgA` (attacker-controlled) and `orgB` (victim), each with its own `webhook_secret`, as supported by `Shipit.github_app_config`.
2. Attacker knows `orgA`'s `webhook_secret` (their own GitHub App/webhook configuration) and observes a public commit SHA `deadbeef...` belonging to a stack under `orgB` that has an outstanding merge request awaiting a required `ci/required-check` status.
3. Attacker computes a valid `X-Hub-Signature` using `orgA`'s secret over a JSON body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "orgA" } }
}
```
4. POSTs this to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: "orgA")` (from `repository.owner.login`) and successfully verifies the signature against `orgA`'s secret [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: "deadbeef...")` — this matches the commit under `orgB`'s stack regardless of the `orgA` binding used for signature verification, and creates a `success` status on it [6](#0-5) .
7. The forged status satisfies `orgB`'s required CI check, enabling `MergeRequest#merge!` to auto-merge the pull request or allowing the commit to be deployed, despite the attacker having no relationship to `orgB`.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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
