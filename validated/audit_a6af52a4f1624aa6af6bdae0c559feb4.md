### Title
Webhook signature verification key is selected from an attacker-controlled field that is decoupled from the repository actually written to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` chooses *which* GitHub App/organization's `webhook_secret` to use for HMAC verification based on a field taken from the same untrusted JSON body it is about to verify. The field used for key-selection (`repository.owner.login`, or `organization.login`) is not the same field the webhook handlers use to decide *which repository/stack gets mutated* (`repository.full_name`). Because both fields live in the attacker-authored raw payload, an actor who legitimately owns the `webhook_secret` for **one** configured GitHub organization on a multi-tenant Shipit instance can forge a payload whose "verification" fields point to their own org (so the signature check passes) while the "target" fields point to a different organization's repository, causing Shipit to mutate that other repository's `Stack`/`Commit`/`Team` state.

### Finding Description
`verify_signature` derives the organization used to pick the webhook secret purely from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), and that string is used to fetch the corresponding `GitHubApp`/`webhook_secret` via `Shipit.github(organization: repository_owner)`. The signature is then checked with that secret against `request.raw_post` — a body the attacker fully controls before signing.

Once verification passes, the entire payload is forwarded unmodified to handlers: [3](#0-2) 

Handlers determine *which repository/stack to act on* using a **different** nested field of the same payload — `repository.full_name` — not `repository.owner.login`: [4](#0-3) 

For example, `PushHandler` resolves the target stacks solely through this `repository_name` (i.e. `repository.full_name`) and updates them: [5](#0-4) 

The same pattern applies to `CheckSuiteHandler` (drives `RefreshCheckRunsJob` scheduling) and the `pull_request` handlers, which all resolve their target via `params.repository.full_name` independently of the field checked during signature verification.

**The binding that should hold:** `organization whose secret authenticated the request == organization that owns the repository being mutated`.
**What actually happens:** these are two different JSON fields (`repository.owner.login` vs `repository.full_name`) inside a single attacker-authored, attacker-signed body — nothing enforces they agree.

This is only exploitable when the Shipit instance is configured for multiple GitHub organizations, which is a documented, in-scope, first-class configuration mode of the engine: [6](#0-5) 

In that mode, each organization possesses its own legitimate `webhook_secret` (via its own GitHub App settings, which that org's admins normally hold and use to configure the webhook endpoint). Because the engine trusts whichever secret matches a field inside the payload rather than binding the signature to a fixed, out-of-band org identity, org A's legitimate secret can be used to sign a payload that claims (via `repository.full_name`) to be about org B's repository.

### Impact Explanation
This breaks the tenant isolation between organizations sharing one Shipit deployment: an entity that only legitimately controls one organization's GitHub App/webhook configuration can forge webhook events that cause Shipit to write to `Stack`/`Commit`/`PullRequest`/`Team` records that belong to a different organization's repository — e.g. triggering `GithubSyncJob`, altering commit statuses, or archiving/unarchiving review stacks for a repository it does not own. This is a cross-repository write across an authentication boundary that Shipit is supposed to enforce per organization, matching the "cross-repository writes" impact criterion.

### Likelihood Explanation
Requires: (1) the Shipit instance configured with multiple GitHub organizations (a documented, supported configuration), and (2) the attacker possessing a valid `webhook_secret` for at least one of those organizations (which they are only expected to use for their own repository's webhooks). No session, `ApiClient` token, `api_clients_secret`, GitHub App private key, or write access to the *target* repository is required — only the attacker's own, legitimately-issued webhook secret for a different, unrelated organization on the same instance.

### Recommendation
Bind webhook signature verification to a fixed, out-of-band organization/repository identity (e.g. resolve the target `Stack`/`Repository` first via `repository.full_name`, look up which organization it belongs to from Shipit's own configuration/DB, and verify the signature using that organization's secret — never trust an attacker-suppliable field to select the verification key). Alternatively, after verification, re-validate that `repository.full_name`'s owner matches `repository_owner` (the field used to select the secret) before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. As an administrator with legitimate access to `orgA`'s GitHub App settings, take `orgA`'s `webhook_secret`.
3. Craft a `push` (or `check_suite`) payload body where:
   - `repository.owner.login` = `"orgA"` (so `verify_signature`/`repository_owner` picks `orgA`'s secret)
   - `repository.full_name` = `"orgB/target-repo"` (the actual repository owned by `orgB` that Shipit tracks)
4. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(orgA_webhook_secret, raw_body)` and POST to `/webhooks`.
5. `verify_signature` succeeds (secret matches org selected from the payload). `PushHandler#stacks` resolves the target via `repository.full_name` = `orgB/target-repo`, and Shipit processes the event (e.g., enqueues `GithubSyncJob`, updates commit/check state) for `orgB`'s stack — despite the request never being signed by `orgB`.

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
