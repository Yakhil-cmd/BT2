## Title
Webhook signature verification is bound to the payload's claimed organization, not to the repository/commit actually mutated, allowing cross-repository status/sync forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a payload against using an **attacker-influenced field of the same unverified payload** (`repository.owner.login`), while the handlers that actually act on the payload key their side effects off a **different** field (`repository.full_name`) or, in the case of `StatusHandler`, off no repository scoping at all. This breaks the intended binding: *the organization whose secret authenticated this webhook* == *the repository/commit that gets written to*.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) using: [1](#0-0) [2](#0-1) 

`repository_owner` is read directly from the JSON body (`params.dig('repository','owner','login')`), i.e. from data that is itself covered by the very signature being computed — so anyone who legitimately controls (or knows the `webhook_secret` of) **any one** GitHub organization configured on this Shipit instance can produce a validly-signed request whose body otherwise contains arbitrary content, as long as `repository.owner.login` equals that organization.

Once signature verification passes, the actual event handlers determine *what gets mutated* using a **different** field, `repository.full_name`: [3](#0-2) 

Nothing ties `repository.full_name` back to the `repository.owner.login`/organization that was used to select the signing secret. `PushHandler` and `CheckSuiteHandler` both resolve target stacks purely from `repository.full_name`: [4](#0-3) [5](#0-4) 

`StatusHandler` is even less scoped — it does not consult `repository` at all and updates the status of **any** commit matching the SHA, regardless of which stack/repository it belongs to: [6](#0-5) 

This mirrors the Ambire bug class: the "signed"/"trusted" scope (an organization's webhook secret authenticating a payload) is not the scope that the code actually acts on (an arbitrary repository/stack/commit named inside that same, attacker-shaped payload).

### Impact Explanation
An attacker who legitimately controls a low-trust GitHub organization that has been onboarded to this shared Shipit instance (or otherwise obtains that organization's `webhook_secret` — the intended, lower trust boundary for that org) can forge validly-signed `push`, `check_suite`, or `status` webhooks whose `repository.full_name` (or, for `status`, whose `sha`) references a stack/commit belonging to a **completely different, more sensitive organization/repository** tracked by the same Shipit instance:
- Via `PushHandler`, they can force `stack.sync_github` to run against a foreign stack.
- Via `CheckSuiteHandler`, they can trigger `schedule_refresh_check_runs!` against foreign commits.
- Via `StatusHandler`, they can set arbitrary CI status (`success`/`failure`/`pending`, with attacker-chosen `context`, `description`, `target_url`) on **any commit in the entire Shipit instance**, since the query is not scoped by repository at all. If merge/deploy gating anywhere in the engine or downstream consumers relies on commit `Status` records, this allows an unprivileged organization to paint a fabricated green check on a commit it does not own, undermining the integrity of another repository's release pipeline — a cross-repository write outside the attacker's authorized scope.

### Likelihood Explanation
Exploitation only requires the attacker to control (or have leaked knowledge of) one organization's `webhook_secret` on a multi-tenant Shipit deployment (a configuration explicitly supported, see `test/dummy/config/secrets_double_github_app.yml`) — no `ApiClient` token, GitHub App private key, or Shipit session is required, satisfying the unprivileged-attacker constraint. The likelihood is highest in multi-organization Shipit setups, which the engine explicitly documents and supports.

### Recommendation
Bind the fields used for authorization/signature-secret selection to the exact same fields used for locating/mutating resources: verify the webhook signature and then re-derive the acting organization from `repository.full_name`'s owner segment (or vice versa), rejecting the request if they diverge. For `StatusHandler`, scope the `Commit` lookup to commits belonging to a `Stack`/`Repository` that matches the authenticated organization, instead of matching by bare SHA across the entire instance.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgLowTrust` and `OrgSensitive` (as in `test/dummy/config/secrets_double_github_app.yml`), each with its own `webhook_secret`.
2. As an admin of `OrgLowTrust`'s GitHub App/webhook, craft a `status` event body:
```json
{
  "sha": "<commit-sha-belonging-to-OrgSensitive-repo>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgLowTrust" }, "full_name": "OrgLowTrust/whatever" }
}
```
3. Sign the raw body with `OrgLowTrust`'s `webhook_secret` and send it as `X-Hub-Signature` to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgLowTrust")` (from `repository.owner.login`) and the signature validates successfully.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — since it never checks `repository`, it updates the status of the `OrgSensitive` commit, even though only `OrgLowTrust`'s secret authenticated the request.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
