## Title
Webhook signature verification is keyed by an attacker-controlled `repository.owner.login`/`organization.login` field, allowing cross-organization spoofing of push/status/check_suite events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App secret to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted JSON body, before the signature has been proven valid for that value. In a multi-organization Shipit deployment (the documented `config/secrets.yml` layout with one sub-key per GitHub organization), any organization that is configured without a `webhook_secret` becomes a skeleton key: `verify_webhook_signature` unconditionally returns `true` when no secret is configured for the resolved organization. An attacker who knows (or guesses) the name of any such secret-less configured organization can submit a completely unsigned webhook whose `repository.full_name` names a *different*, unrelated, secret-protected repository/stack, and have it processed as genuine.

### Finding Description
`repository_owner`, used solely to pick the verification key, is untrusted input: [1](#0-0) 

The signature check itself: [2](#0-1) 

And in `GitHubApp`, when no `webhook_secret` is configured for the resolved organization, verification is bypassed entirely: [3](#0-2) 

Multi-org support is documented and expected — each organization key in `secrets.github` has its own independent `webhook_secret`: [4](#0-3) 
and the secret is explicitly called "optional" in setup instructions: [5](#0-4) 

Once `verify_signature` passes (because the org resolved from the payload has no secret configured), `create` dispatches the raw, attacker-supplied JSON straight to the event handlers: [6](#0-5) 

Crucially, the handlers determine the *target* repository from a **separate** field — `repository.full_name` — that is never cross-checked against `repository.owner.login` used for signature-key selection: [7](#0-6) 

This is exactly the binding break called out in the prompt: "an organization that authenticated versus the repository that is written." The organization used to select/validate the cryptographic proof (`repository.owner.login` for key lookup) is not the same value bound to the side effects that follow (`repository.full_name`, resolved to `Repository`/`Stack` records via `Repository.from_github_repo_name`).

Concretely, `PushHandler` uses `repository_name` (via `stacks`) to trigger `stack.sync_github(expected_head_sha:)` on any non-archived stack matching the branch: [8](#0-7) 

`StatusHandler` creates a commit status purely from `sha`, with no repository binding at all — any commit sha in the whole install, regardless of which repo it belongs to, can have a forged CI status attached: [9](#0-8) 

`CheckSuiteHandler` similarly resolves `stacks` (again by `repository.full_name`) independently of the owner used for signature verification: [10](#0-9) 

### Impact Explanation
This qualifies as High severity under the given rubric: "unauthenticated read of stack state, task streams or deploy output" is exceeded here — it is actually unauthenticated **write**/forgery of build state. Concretely, an attacker who has no GitHub App credentials, no `webhook_secret`, and no repository write access to the target repo can:
- Forge a `push` webhook naming any tracked repository/stack (via `repository.full_name`), causing Shipit to sync from GitHub and potentially trigger continuous-deployment logic driven by `sync_github` for a repository they don't control the org secret of.
- Forge `status` events for arbitrary commit shas, poisoning CI status used to gate the merge queue / continuous deployment decisions (`commit.create_status_from_github!`).
- Forge `check_suite` completions to force `schedule_refresh_check_runs!` for stacks belonging to any organization, as long as some other organization in the multi-tenant config lacks a webhook secret.

This is an authentication-boundary break between "the organization Shipit thinks it verified" and "the repository Shipit actually acts on," directly analogous to the report's core theme: a value used to authorize an action is not the same value the signature actually protects/binds.

### Likelihood Explanation
Requires:
1. The deployment to use the documented multi-organization `secrets.github` schema (explicitly supported and documented).
2. At least one configured organization to have `webhook_secret` unset (explicitly documented as "optional").
3. Attacker knowledge of that organization's login name (often discoverable, e.g., via the Shipit UI's stack list or GitHub itself) and the target repository's `full_name`.

Given the feature and the "optional" secret are both intentional, first-party documented configurations, this is realistically reachable without any privileged token, session, or GitHub App key — matching the "unprivileged attacker" scope of this exercise. Likelihood is Medium-High in any multi-org install where not every org's webhook secret has been set (a case the docs neither warn against nor the code defends against).

### Recommendation
- Do not select the verification secret using an unauthenticated field from the same payload being verified without a signed guarantee of that value; if a multi-org config is used, either (a) require `webhook_secret` to be mandatory for all configured organizations (fail closed instead of returning `true` when absent), or (b) verify the signature against *every* configured organization's secret and only accept if at least one matches AND that same organization owns the `repository.full_name` being processed.
- Bind the value used for signature/organization resolution to the value used to resolve the target repository (i.e., ensure `repository.owner.login` and the owner portion of `repository.full_name` are the same and both validated against the org whose secret matched).
- Change `GitHubApp#verify_webhook_signature` to fail closed (return `false`/raise) when `webhook_secret` is blank, rather than treating an unconfigured secret as "always trusted."

### Proof of Concept
Given a `secrets.github` config with two organizations, e.g.:
```yaml
github:
  trusted-org:
    webhook_secret: real-secret-value
    ...
  legacy-org:
    webhook_secret:   # left blank/unset ("optional" per docs/setup.md)
    ...
```
An attacker, with no credentials, sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything-or-omitted
Body:
{
  "repository": {
    "owner": { "login": "legacy-org" },
    "full_name": "trusted-org/super-secret-app"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
- `verify_signature` resolves `repository_owner => "legacy-org"`, builds `Shipit.github(organization: "legacy-org")`, whose `webhook_secret` is blank → `verify_webhook_signature` returns `true` unconditionally regardless of the signature header.
- `create` then dispatches the payload to `PushHandler`, which resolves `repository_name => "trusted-org/super-secret-app"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the real, unrelated `trusted-org` stack — an action the attacker was never authorized to trigger and could not have triggered by knowing `trusted-org`'s (real) webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
