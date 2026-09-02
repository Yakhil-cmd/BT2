### Title
Webhook signature verification is bound to an attacker-supplied `organization`/`repository.owner.login` field that is disconnected from the repository/commit the payload actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App config (and thus which `webhook_secret`) to verify a webhook against using a field read straight out of the untrusted JSON body, while the handlers that actually act on the payload (`StatusHandler`, `PushHandler`, `CheckSuiteHandler`) resolve the target commit/repository from a *different* field of the same body. Because `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected org has no `webhook_secret` configured, an attacker can pick an org with no secret to sail through "verification" and then, independently, address any commit/repository tracked by the Shipit instance.

### Finding Description
`repository_owner` — the only value used to select which app config verifies the signature — is derived entirely from the request body: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` bypasses HMAC checking entirely when the selected app config has no secret set: [3](#0-2) 

The setup docs confirm `webhook_secret` is explicitly optional per-organization in a multi-org config: [4](#0-3) 

Meanwhile, the handlers that actually mutate state key off a *different* field pair from the same JSON body, with no cross-check against `repository_owner`:
- `PushHandler`/generic `Handler#stacks` resolve the target `Repository`/`Stack` purely from `payload.dig('repository','full_name')`: [5](#0-4) 
- `StatusHandler` doesn't even scope by repository — it matches **any** `Commit` in the entire installation by SHA alone and writes a status onto it: [6](#0-5) 
- `CheckSuiteHandler` similarly resolves stacks via `Handler#stacks` (i.e. `repository.full_name`), independent of `repository_owner`: [7](#0-6) 

This is the same bug class as the `Looping.openPosition()` report: a value used to satisfy a validation gate (`minAmountOut` derived from `_flashloanAmount`/`_minAmountOut`) is computed from a field that doesn't correspond to what the transaction actually acts on (`_initialAmount` in a different asset). Here, the field used to satisfy the "verification" gate (`repository_owner`/`organization.login`, used only to pick a signing secret) is decoupled from the field the code actually acts on (`repository.full_name`, or nothing at all for `StatusHandler`). The equality that should hold — `organization authenticated == repository/commit written` — is broken.

### Impact Explanation
In any deployment using the multi-organization GitHub config (documented and supported, `lib/shipit.rb#github_app_config`) where at least one configured organization is left without a `webhook_secret` (an explicitly "optional" and documented setting), an unauthenticated internet attacker can POST directly to `/webhooks` with `X-Github-Event: status` (no signature header required at all, since `verify_webhook_signature` returns `true` before ever inspecting the header) and a body such as:
```json
{"organization": {"login": "org-without-secret"},
 "sha": "<any commit sha tracked by any stack in the instance>",
 "state": "success", "context": "ci/required-check"}
```
`repository_owner` resolves to `org-without-secret` (bypassing HMAC), while `StatusHandler` writes a fabricated `success` status onto the targeted commit regardless of which repository/organization it actually belongs to. If that commit belongs to a stack with `continuous_deployment` enabled and status-gated (`ci.require`/`ci.blocking`, see `app/models/shipit/deploy_spec.rb`), this forged status can satisfy the CI gate and trigger an unauthorized automatic deploy — meeting the "unauthorized deploy" Critical-impact bar. Even absent continuous deployment, this is an unauthenticated write of arbitrary commit/task state across every repository hosted by the instance, meeting the High-impact bar ("unauthenticated read/write of stack state").

### Likelihood Explanation
Medium-High: no credentials, session, or secret are required by the attacker — only that the operator's multi-org GitHub config contains one organization without a `webhook_secret`, which the setup documentation itself presents as a normal, optional configuration choice rather than a hardening requirement. An attacker only needs to know (or guess/enumerate) one such unsecured `organization.login` value and a target commit SHA (visible on the public Shipit UI/API for any tracked stack).

### Recommendation
- Require `webhook_secret` to be mandatory for every configured GitHub App/organization (fail closed instead of `return true unless webhook_secret` in `lib/shipit/github_app.rb`).
- Bind signature verification to the same repository/commit identity that handlers act on: after verifying the signature for `repository_owner`, re-validate that `payload.dig('repository','full_name')`'s owner matches the verified `repository_owner`/`organization.login`, and reject otherwise.
- Scope `StatusHandler#process` (and any handler resolving by SHA alone) to commits belonging to the verified repository, not a global `Commit.where(sha:)` lookup.

### Proof of Concept
1. Operator configures multiple GitHub orgs per `docs/setup.md`, with `orgB` deliberately or accidentally left with `webhook_secret: nil` (an explicitly optional field).
2. Attacker sends, with no `X-Hub-Signature` header:
```
POST /webhooks HTTP/1.1
X-Github-Event: status
Content-Type: application/json

{"organization":{"login":"orgB"},
 "sha":"<sha of a commit in stack for orgA/some-repo>",
 "state":"success","context":"ci/blocking-check"}
```
3. `repository_owner` resolves to `orgB`; `Shipit.github(organization: 'orgB').verify_webhook_signature(...)` returns `true` immediately because `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`), regardless of `orgA`'s repository being the actual target.
4. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) finds the commit by `sha` alone (no org/repo check) and creates a fabricated success status on it, potentially unblocking continuous deployment for `orgA/some-repo`.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
