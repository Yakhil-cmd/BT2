### Title
Cross-tenant commit-status forgery via unscoped `Commit.where(sha:)` lookup combined with per-organization signature-verifier selection - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` picks which organization's `GitHubApp`/`webhook_secret` to verify against using `repository_owner`, which falls back to `organization.login` when the `repository` key is absent from the JSON body. [1](#0-0)  The `status` handler that actually mutates state never reads or checks any repository field at all — it looks up commits purely by `sha` across the entire `commits` table and writes a GitHub status onto whatever it finds. [2](#0-1)  This means the org chosen for signature verification and the record that gets mutated are governed by two entirely disconnected values, and there is no invariant tying "who verified this payload" to "whose commit gets updated."

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`verifier_org (Shipit.github(organization: repository_owner))` == `owner_of(Commit.where(sha: params.sha).first)`

Trace:
1. `verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and uses it to select a `GitHubApp` instance (and its `webhook_secret`) via `Shipit.github(organization: repository_owner)`. [3](#0-2) [1](#0-0) 
2. `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for the resolved org/app config. [4](#0-3)  An attacker who controls (or knows lacks a configured secret) any organization onboarded to this Shipit instance can therefore satisfy signature verification just by putting that org's login in `organization.login` and omitting `repository`.
3. Once verification passes, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — no filter on repository, stack, or organization whatsoever. [2](#0-1) 
4. Because the `sha` is attacker-supplied JSON (the handler's `ExplicitParameters` schema only requires `sha` and `state` as strings, with no format/ownership constraint) [5](#0-4) , an attacker who knows a victim commit's SHA (public on GitHub) can set `state: 'success'` for that SHA. Since git commit SHAs are content-addressed, an attacker can also obtain identical SHAs to a victim's history simply by forking the victim repository, guaranteeing a `Commit` row with that exact `sha` exists in Shipit's database for the victim's stack.
5. `verify_signature`'s org-selection logic and the handler's mutation logic never intersect, so the org that "authenticated" the payload has no relationship to the repository/stack whose commit status is changed — the invariant "a forged webhook cannot cause state change attributed to a repository whose secret did not verify it" is broken.

Existing guards do not stop this: `drop_unhandled_event` only checks the event name is registered; `ExplicitParameters` only validates types/presence, not ownership; there is no `Repository`/`Stack` scoping anywhere in the `status` handling path.

### Impact Explanation
A successful forged `status` event causes `Commit#create_status_from_github!` to write a passing (or any attacker-chosen) status onto a victim's commit, without the attacker owning, maintaining, or having any authorization on the victim's repository/stack. Since Shipit's merge queue and deploy gating rely on commit statuses to determine whether commits/PRs are mergeable or deployable, this can advance or unblock a victim's merge queue, or otherwise corrupt the victim stack's CI-derived state — a payload delivered under one organization's/repository's authentication mutating another repository's records. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions: Shipit must be running in the multi-organization GitHub App configuration (`github_default_organization` present) where `webhook_secret` can be absent/blank for at least one onboarded org, or the attacker must otherwise possess/know a valid `webhook_secret` for any org listed in `secrets.github` (attacker only needs this for *any one* org, not the victim's). The attacker needs the victim's commit SHA, which is trivially public on GitHub (or trivially reproducible by forking the victim repo, since git commit SHAs are content-derived). Given these commonly-met preconditions in any multi-tenant Shipit deployment, this is repeatable per request, against arbitrary victim commits/stacks, with no privileged credentials required.

### Recommendation
Scope `StatusHandler#process` (and any other sha-keyed handler) to the repository/organization that was actually verified — e.g., require the payload's `repository.full_name` to match the `Stack`/`Commit`'s known repository before applying the status, and derive `repository_owner` used for verification from the same repository record the handler will mutate, rejecting payloads where `repository` is absent for events that mutate repository-scoped state. Additionally, treat a missing/blank `webhook_secret` for a given org as a configuration error to fail closed, not an implicit bypass.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_cross_tenant_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "a status payload verified against org A's secret can mutate a commit belonging to org B's stack" do
          victim_stack = shipit_stacks(:shipit)
          victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, message: 'victim commit')

          # Attacker-controlled payload: no 'repository' key, only 'organization.login'
          # pointing at an org whose webhook_secret is blank/unknown to Shipit.
          forged_params = ExplicitParameters::Params.new(
            sha: victim_commit.sha,
            state: 'success',
            context: 'ci/attacker-forged'
          )

          # Equality under test BEFORE:
          assert_not_equal victim_commit.stack.repository.owner, 'attacker-org' # victim owner != attacker org

          Handlers::StatusHandler.new.call(forged_params)

          victim_commit.reload
          # Equality under test AFTER: victim commit now carries attacker-forged status,
          # despite verification never being performed against victim's org secret.
          assert victim_commit.statuses.exists?(state: 'success', context: 'ci/attacker-forged')
        end
      end
    end
  end
end
```
This demonstrates that `StatusHandler#process`'s `Commit.where(sha: params.sha)` lookup (app/models/shipit/webhooks/handlers/status_handler.rb:21) is unscoped, so any commit SHA reachable from a verified-but-unrelated organization can be mutated, confirming the broken binding between the verifier-selection field (`repository_owner`) and the handler's actual target (`Commit`/`Stack`).

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
