### Title
Webhook signature verification binds to the wrong organization, allowing cross-organization commit-status/webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an incoming webhook's HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the *unverified* JSON body. Nothing ties that value to the repository/commit that the corresponding event handler actually mutates. In particular, `StatusHandler#process` looks up commits globally by SHA (`Commit.where(sha: params.sha)`) with no repository scoping at all, and `PushHandler`/`CheckSuiteHandler` resolve the target repository from a different payload field (`repository.full_name`) than the one used for signature selection. An attacker who legitimately owns *any* GitHub organization/repo onboarded to this Shipit instance (and therefore knows that org's `webhook_secret`) can forge a validly-signed webhook whose `repository.owner.login` is their own org, but whose actual event content (e.g. a commit `sha`) targets a totally different organization's stack.

### Finding Description
The binding that should hold is:

`organization used to select the webhook_secret for signature verification == organization that owns the repository/commit the handler writes to`

Before the fix, both sides used the same trusted GitHub-emitted payload, so they matched by construction. Here, the equality is never actually checked in code:

- `verify_signature` derives the signing organization purely from payload content it has not yet verified: [1](#0-0) [2](#0-1) 

- `StatusHandler` never scopes by repository at all — it matches on SHA across the entire `commits` table: [3](#0-2) 

- `PushHandler` and `CheckSuiteHandler` resolve the target stacks via `repository.full_name` (a different payload field than `repository.owner.login`), through `Handler#stacks`/`#repository_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

Because `repository.owner.login` (used only to pick which secret validates the HMAC) and the field(s) actually used to locate the target commit/stack (`sha`, `repository.full_name`) are independent JSON keys inside the same attacker-controlled body, an attacker who can produce a valid signature for *their own* org's secret can freely choose values for the other fields to target any repository/stack tracked by the same Shipit instance — including ones belonging to organizations whose `webhook_secret` the attacker does not know.

### Impact Explanation
This is High impact: it lets an unprivileged attacker (who only needs to control one GitHub org/repo already onboarded to the target Shipit instance) forge a `status` webhook that plants a fabricated "success"/"pending"/"failure" `CommitStatus` on a commit belonging to a stack in a completely different, unrelated GitHub organization, by simply guessing/using a public commit SHA of that target repo. Since `ci.require` / `ci.blocking` gate deploy eligibility on such statuses (see README `ci.require`), this can satisfy CI requirements for a commit the attacker does not control and enable an unauthorized deploy path, or corrupt the deploy/CI history shown to legitimate operators. It also lets an attacker trigger `RefreshCheckRunsJob`/`GithubSyncJob` side effects (via `PushHandler`/`CheckSuiteHandler`) against stacks outside their own organization, since those handlers key off `repository.full_name`, a field never cross-checked against the organization whose secret validated the signature.

### Likelihood Explanation
Low-to-moderate: it requires the attacker to already have legitimate write/admin access to at least one GitHub organization/repository that is itself registered in the same Shipit instance (so they can configure/know that org's `webhook_secret`, e.g., via their own repo's webhook settings if Shipit auto-configures webhooks, or by being a repo admin who set it up). This is a much lower bar than a privileged Shipit account or GitHub App key, but does require multi-tenant usage of a single Shipit deployment across independent GitHub orgs that don't trust each other, which is a documented supported configuration (`Shipit.github(organization:)` is per-organization).

### Recommendation
Do not select the verifying secret from unauthenticated payload fields whose only role should be identification for routing an already-verified request. Instead, verify the signature using the destination route/host or a strict comparison, and additionally re-check that every organization/repository field referenced during handler processing (`repository.full_name`, `sha`'s owning stack, `check_suite.head_sha`'s owning stack, etc.) belongs to the same organization that owns the secret used to verify the signature — reject the event otherwise. Concretely, after verification, assert `repository.owner.login == Repository.find_by(full_name: repository.full_name)&.owner`, and scope `StatusHandler`'s commit lookup to `stacks` (repository-scoped) instead of a bare `Commit.where(sha: ...)`.

### Proof of Concept
1. Attacker owns/administers GitHub org `attacker-org`, which is onboarded to the shared Shipit instance and has its own `webhook_secret` (`S_attacker`), known to the attacker.
2. Victim org `victim-org` also uses the same Shipit instance, with a stack tracking a public repo and a known head commit SHA `abcd1234...` that is required to pass `ci.require: [ci/circleci]` before deploy.
3. Attacker crafts a JSON body:
```json
{
  "sha": "abcd1234...",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(S_attacker, body)` and sends it as a `status` event to `POST /github/webhooks`.
5. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature against `S_attacker` — `head(422)` is never called. [1](#0-0) 
6. `StatusHandler#process` runs `Commit.where(sha: "abcd1234...")`, which matches the victim's commit (no repo scoping), and calls `commit.create_status_from_github!(params)`, injecting a forged `success` status for `ci/circleci` on `victim-org`'s commit. [3](#0-2) 
7. If continuous delivery is enabled on the victim stack, this forged status can unblock/trigger an unauthorized deploy of that commit.

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
