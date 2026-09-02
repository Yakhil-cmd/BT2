### Title
Webhook signature verification is keyed to an attacker-chosen GitHub organization, while the events processed act on unrelated repositories/commits — allowing forged status/push events across the whole instance - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to verify a webhook's HMAC signature against based on a value taken from the *attacker-supplied JSON body* (`repository.owner.login`, or `organization.login`), not from anything tied to the actual repository/commit the event handler subsequently acts on. Because `GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatically verified (`return true unless webhook_secret`), and because handlers such as `StatusHandler` key their side effects purely off attacker-controlled fields (`sha`) with no repository scoping at all, an attacker can pick any organization slot in a multi-org config that has no `webhook_secret` configured, "authenticate" under that org, and then supply payload fields that cause the engine to act on a completely different, real repository/commit/stack.

### Finding Description
The binding that should hold is: *the organization whose secret verified the webhook signature == the organization/repository the resulting handler acts on*. This binding is broken:

1. `verify_signature` picks the org to verify against from the payload itself: [1](#0-0) [2](#0-1) 

2. `GitHubApp#verify_webhook_signature` unconditionally passes when that org's `webhook_secret` is blank: [3](#0-2) 

The setup docs explicitly document configuring `webhook_secret:` as optional/nil, and the multi-org config format has independent `webhook_secret` per org: [4](#0-3) [5](#0-4) 

3. Once past `verify_signature`, the actual handler dispatch uses a *different* field of the same attacker-controlled body to decide what real-world object to mutate. For example `PushHandler`/base `Handler` resolves the target `Repository`/`Stack` from `repository.full_name`, not from the `repository_owner` used for signature selection: [6](#0-5) [7](#0-6) 

Worse, `StatusHandler` doesn't even scope by repository — it looks up commits globally by `sha` across the entire installation and writes a GitHub commit status onto them: [8](#0-7) 

Since `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` / `sha` (used by the handler to select the real target) are independent JSON fields in a POST body fully controlled by the caller, nothing forces them to agree. An attacker who is aware of, or can enumerate, any configured GitHub organization slot in `secrets.yml` that has no `webhook_secret` set (this is explicitly supported/documented as optional) can:
- Set `X-Github-Event: push` (or `status`), no `X-Hub-Signature` needed since a blank secret auto-verifies.
- Set `repository.owner.login` (or `organization.login`) to the org with the blank secret, so `verify_signature` passes.
- Set `repository.full_name` (push handler) or `sha` (status handler) to reference a real, unrelated, victim stack/commit hosted under a different, properly-secured organization.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding described in scope. Concretely:
- Via `StatusHandler`, an attacker can forge a passing CI status (`state: success`) for an arbitrary commit SHA belonging to any stack in the Shipit instance, without ever passing signature verification tied to that stack's real organization/secret. Shipit's commit deployability and `ci.require` gating are driven by these persisted commit statuses (as documented in `README.md`'s CI section), so this can make an otherwise non-deployable/malicious commit appear deployable to continuous deployment logic (`ContinuousDeliveryJob#perform` gates only on `stack.continuous_deployment?`/schedule/occupancy, not on which org signed the webhook that produced the status): [9](#0-8) 
- Via `PushHandler`, an attacker can trigger `GithubSyncJob`/`sync_github` against an arbitrary target stack while only holding a signature that verifies for an unrelated, weakly-configured org.

This maps to the Critical bucket "an unauthorized deploy, rollback, or merge" because forged CI status directly feeds the automatic-deploy decision path for continuously-deployed stacks, and to the High bucket "unauthenticated read/write of stack/task state" for the broader webhook-driven state mutation (team/user/membership creation, PR/review-stack archiving, etc., all reachable the same way).

### Likelihood Explanation
Requires only knowledge that the deployment is configured with the multi-org `github:` schema and that at least one configured org entry omits `webhook_secret` (explicitly presented as optional in the shipped example config and docs), plus the target victim's repository full name/branch or a target commit SHA (visible on GitHub, a public source in most cases). No credentials, GitHub App private key, or Shipit API token are required — only an unauthenticated POST to `/webhooks`. This is a realistic, low-effort operator-misconfiguration-adjacent but code-level design flaw: the code itself decouples "who verified" from "what gets mutated," rather than the host failing to mount something as documented.

### Recommendation
- Derive the verifying organization deterministically from the same repository identity the handler will act on (i.e., always use `repository.full_name`'s owner segment, single source of truth), and reject events where `repository.owner.login`/`organization.login` disagree with `repository.full_name`'s owner.
- Do not treat a blank `webhook_secret` as "verified" — require every configured org (or globally) to have a webhook secret, or reject signature-less requests for any org actually associated with an existing `Repository`/`Stack` record.
- Scope `StatusHandler` (and any other handler) commit/stack lookups to the repository asserted in the same verified payload, not open-ended global lookups by `sha`.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has `webhook_secret: <real secret>`, owns a real stack with `continuous_deployment: true`), and `attacker-org` (has `webhook_secret:` left blank — a supported, documented configuration).
2. POST to `/webhooks` with header `X-Github-Event: status` and no (or garbage) `X-Hub-Signature`, body:
```json
{
  "organization": { "login": "attacker-org" },
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `verify_signature` resolves `repository_owner` to `attacker-org` (`app/controllers/shipit/webhooks_controller.rb:59-62`), calls `Shipit.github(organization: 'attacker-org').verify_webhook_signature(...)`, which returns `true` unconditionally because `attacker-org`'s `webhook_secret` is blank (`lib/shipit/github_app.rb:76-83`).
4. `StatusHandler#process` then runs unscoped: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), writing a forged "success" status onto the victim's commit even though the request was never signed with `victim-org`'s secret.
5. If that commit is the head of a continuously-deployed stack and this forged status satisfies `ci.require`, the next `ContinuousDeliveryJob` run can trigger an unauthorized deploy.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```
