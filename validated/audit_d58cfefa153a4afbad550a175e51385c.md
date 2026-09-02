### Title
Webhook signature verification org does not match the repository the event is applied to, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to validate the HMAC signature by reading `repository.owner.login` (or `organization.login`) directly out of the untrusted request body, but the event handlers that actually act on the payload (via `Handler#repository_name`) key off a *different* field of that same untrusted body — `repository.full_name`. These two values are never checked for consistency, so signature verification authenticates one organization while the mutation is applied to a repository/stack that can belong to a different, unrelated organization configured on the same Shipit instance.

### Finding Description
`verify_signature` picks the app used to validate `X-Hub-Signature` based on `repository_owner`, which is parsed straight from the attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

Once the signature is validated (successfully, using whichever org's `webhook_secret` matches `repository_owner`), the raw payload is dispatched unchanged to handlers: [3](#0-2) 

Every handler resolves the target `Stack`/`Repository` using an entirely separate field of the same body, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits `owner/name` out of that string and looks up the DB row: [5](#0-4) 

`PushHandler`, for example, then queues a `GithubSyncJob`-style sync with an attacker-controlled `expected_head_sha` for every branch-matching stack under whatever repository `full_name` names: [6](#0-5) 

**The broken binding, stated as an equality that the code assumes but never enforces:**
`organization authenticated by verify_signature (repository.owner.login)` == `organization of the repository the handler mutates (repository.full_name)`.

Before the attacker's crafted request, this equality always held because GitHub itself generates consistent `owner.login`/`full_name` fields. After a forged request, an attacker who knows the `webhook_secret` for *any one* organization configured in this Shipit instance (e.g., their own low-privilege org, which is legitimately connected to the same install per the documented multi-org configuration) can set `repository.owner.login` to that known org (so `verify_signature` passes) while setting `repository.full_name` to `"other-org/other-repo"` — a stack belonging to a completely different organization they have no access to. `Shipit.github(organization: repository_owner)` in `verify_signature` only ever reads the config for the claimed (attacker-chosen) org, so the HMAC check has no relationship to the repository actually acted upon.

### Impact Explanation
This is an authentication-bypass class issue: the webhook authentication check is supposed to prove "this event genuinely originates from GitHub for repository X," but it only proves "this event was HMAC-signed by an org whose secret the sender knows," decoupled from the repository the event will actually mutate. In a Shipit deployment hosting multiple GitHub organizations (a documented, supported configuration — `docs/setup.md`, "Using Multiple Github Applications"), an attacker with legitimate, low-privileged access to one configured org's webhook secret can forge `push`/`status`/etc. events against stacks belonging to a different org they have no rights to, e.g. triggering `sync_github` with an attacker-chosen `expected_head_sha`, or injecting spoofed CI/`status` events. This crosses the "unauthorized deploy" / "authentication bypass" impact bar defined in scope.

### Likelihood Explanation
Requires: (1) the target Shipit install to be configured with more than one GitHub organization (a supported, real-world configuration), and (2) the attacker to control/administer at least one of those configured (lower-privileged) organizations enough to obtain its `webhook_secret` and craft a raw POST with a matching HMAC — both are plausible for an "unprivileged" outside attacker relative to the victim org, since Shipit is explicitly designed to let separate orgs onboard themselves. No `ApiClient` token, session, or GitHub App private key is needed; only knowledge of one org's `webhook_secret`, and no code in `verify_signature` or the handler layer ties the two fields together.

### Recommendation
- Short term: In `WebhooksController#verify_signature`, or centrally in `Handler`, assert that `repository_owner` (used to select the signing org/secret) is identical to the owner segment of `repository.full_name` (used to resolve the target `Stack`) before dispatching to any handler; reject the request otherwise.
- Long term: Verify signatures using the org/secret that owns the *resolved* `Repository`/`Stack` record (looked up first from `full_name`), rather than trusting an org identifier taken directly from the unauthenticated payload, so that signature validation is always scoped to the actual resource being mutated.

### Proof of Concept
1. Assume a Shipit instance configured with two GitHub orgs, `attacker-org` (secret `S_A`, known to the attacker because they administer that org/app) and `victim-org` (secret `S_B`, unknown to the attacker), per the multi-org config format in `docs/setup.md`.
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/production-app"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, raw_body)` — valid, because `verify_signature` resolves `Shipit.github(organization: "attacker-org")` from `repository.owner.login` (`app/controllers/shipit/webhooks_controller.rb:25-30,59-62`) and this matches the secret the attacker used.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` passes.
5. `PushHandler#process` runs, resolving the target via `payload.dig('repository','full_name')` = `"victim-org/production-app"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, `app/models/shipit/repository.rb:53-56`), and queues a sync with the attacker-supplied `after` SHA against `victim-org`'s stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite the attacker never having proven any relationship to `victim-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
