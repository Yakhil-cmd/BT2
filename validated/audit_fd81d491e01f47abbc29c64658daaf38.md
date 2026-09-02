### Title
Webhook signature-verification org selection is not bound to the repository the payload actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to validate an inbound webhook against based on `repository.owner.login` (or `organization.login`), but every event handler that actually mutates data resolves its target `Repository`/`Stack` from the independent `repository.full_name` field. Because these two fields are never cross-checked, and because a per-organization `webhook_secret` is documented as optional (`Shipit.github(organization:).verify_webhook_signature` returns `true` when no secret is configured), an attacker who can get an unsigned/loosely-signed webhook accepted for one configured GitHub organization can make the payload's `repository.full_name` point at a stack belonging to a completely different, secret-protected organization.

### Finding Description
`verify_signature` derives the org used for HMAC verification purely from attacker-controlled JSON, before the signature is actually checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up that org's app config and builds/reuses a `GitHubApp` whose `verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is blank — which the setup docs explicitly call optional (`Webhook secret (optional)`, and `webhook_secret: # nil` in the sample multi-org config): [3](#0-2) [4](#0-3) 

Once `verify_signature` passes (using the *authenticating* organization's key, chosen from `repository.owner.login`/`organization.login`), the actual handler dispatch and target-resolution logic uses a *different* field, `repository.full_name`, to find the `Repository`/`Stack` that gets written to: [5](#0-4) [6](#0-5) 

The same split exists in every handler that scopes by repository, e.g. `PullRequest::ClosedHandler#repository` and `CheckSuiteHandler#process`: [7](#0-6) [8](#0-7) 

Genuine GitHub webhooks always keep `repository.owner.login` and the owner segment of `repository.full_name` consistent, so this split is invisible in normal operation. Nothing in Shipit enforces that consistency itself — it's implicit trust in the fact that the payload came from the org whose secret verified it. The binding that should hold is:
`organization authenticated (repository.owner.login/organization.login, verified via HMAC) == repository actually written to (repository.full_name, used by handlers)`.
That equality is never checked in code.

### Impact Explanation
This engine explicitly supports hosting **multiple, independently-configured GitHub Apps/organizations** in one Shipit instance (`docs/setup.md`, "Using Multiple Github Applications"; `lib/shipit.rb:170-200`), each with its own `webhook_secret` — the stated purpose of per-org keys is trust isolation between organizations sharing one Shipit deployment. If any single configured organization is left with `webhook_secret: nil` (documented as an accepted/optional value), that organization becomes a skeleton key: any unauthenticated internet client can POST to `/webhooks` with `X-Github-Event` set to `push`, `pull_request`, `status`, or `check_suite`, set `repository.owner.login`/`organization.login` to the unsecured org, and set `repository.full_name` to any *other*, fully-secured organization's repository. `verify_signature` passes (secret-less org always verifies), and the handler then acts on the spoofed repository:

- `PushHandler` triggers `GithubSyncJob` (re-syncs commits) for a stack the attacker doesn't control.
- `StatusHandler` writes arbitrary commit statuses (`Commit#create_status_from_github!`) for any commit in a victim stack, which can influence deployability/CI gating decisions surfaced to legitimate operators performing deploys.
- `PullRequest::ClosedHandler`/other PR handlers can archive review stacks or mutate labels/PR state for a victim repository's review stacks.
- `CheckSuiteHandler` schedules check-run refreshes for arbitrary victim commits.

These are unauthenticated cross-repository writes into stacks/records belonging to an organization whose webhook secret the attacker never had — the same class of bug as the Templedao report (a caller-supplied identifier that the access-control check never actually binds to the funds/records ultimately moved).

### Likelihood Explanation
Exploitation requires no privileged account, no `ApiClient` token, and no session — only that the Shipit deployment hosts more than one GitHub organization and that at least one of them has an unset `webhook_secret` (an explicitly supported, documented configuration). Given `webhook_secret` is marked optional in every secrets example file, and the "Using Multiple Github Applications" feature is a first-class documented deployment shape, this is a realistic operator misconfiguration rather than a theoretical one — but it is conditional on that misconfiguration, so it should be scored as an authorization/binding defect in the code rather than a certainty in every deployment.

### Recommendation
- After `verify_signature` succeeds, re-derive the organization from the same field the handlers use (`repository.full_name`'s owner segment, or `organization.login`) and reject the request (422) if it does not match the organization whose secret verified the signature.
- Stop allowing `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank in a multi-organization configuration; either require a secret for every configured org or fail closed when more than one org is configured and any of them lacks a secret.

### Proof of Concept
Given a Shipit instance configured with two orgs, `OpenOrg` (no `webhook_secret`) and `SecureOrg` (real webhook secret, containing the target stack for repository `SecureOrg/prod`):

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json
(no X-Hub-Signature required/valid signature not checked)

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OpenOrg" },
    "full_name": "SecureOrg/prod"
  }
}
```

- `verify_signature` computes `repository_owner = "OpenOrg"`, calls `Shipit.github(organization: "OpenOrg")`, whose `verify_webhook_signature` returns `true` unconditionally (no `webhook_secret` configured for `OpenOrg`) — request passes with `head(:ok)`, no valid signature required.
- `PushHandler#stacks` resolves `Repository.from_github_repo_name("SecureOrg/prod")` and enqueues `GithubSyncJob` against `SecureOrg`'s real production stack, even though the request was never authenticated by `SecureOrg`'s webhook secret. [1](#0-0) [5](#0-4)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-9)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
