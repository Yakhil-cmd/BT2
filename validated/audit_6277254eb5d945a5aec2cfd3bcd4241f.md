### Title
Webhook signature secret selected from an unauthenticated payload field lets one organization's secret authorize actions against another organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` chooses *which* organization's HMAC secret to use for validating an inbound GitHub webhook based on a field read out of the very same untrusted JSON body it is about to verify. Event handlers then act on a *different* field of that same body (`repository.full_name`) to decide which Shipit `Stack`/`Repository` to mutate. Nothing ties "the organization whose secret validated this request" to "the repository the handler is about to touch," so a valid signature computed with organization A's webhook secret can be replayed to drive webhook side effects against organization B's stacks.

### Finding Description
`verify_signature` picks the `GithubApp` (and therefore the HMAC secret) to check against `X-Hub-Signature` purely from attacker-controlled payload content: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`) — a value that lives *inside* the raw body being signed, not something independently supplied by the transport or route. Because `Shipit.github(organization: repository_owner)` is what supplies the secret used for the HMAC check, whichever organization value the attacker puts in that field determines which secret must match.

Downstream handlers, however, resolve the target of the webhook using a *different* field of the same body: `repository.full_name`: [3](#0-2) [4](#0-3) 

Nothing enforces that `repository.owner.login` (used to pick the verifying secret) is the actual owner encoded in `repository.full_name` (used to pick the affected `Stack`). In a legitimate GitHub-originated payload these are always consistent, but the controller trusts the payload itself to tell it which secret to check against — it does not derive the owner from any GitHub-App-specific, out-of-band context (e.g., installation ID, route parameter, or App identity). An attacker who legitimately controls one organization's GitHub App/webhook secret configured in this Shipit instance (call it org A — a normal, unprivileged tenant in a multi-org Shipit deployment, as evidenced by `Shipit.github(organization: ...)` supporting multiple configured organizations and by fixtures like `test/fixtures/shipit/github_hooks.yml` showing multiple orgs) can craft a POST to `/webhooks` where:
- `repository.owner.login` (or `organization.login`) = `"org-a"` (their own, so `verify_signature` loads org A's secret),
- the HMAC signature is computed correctly over the whole raw body using org A's own secret (which the attacker legitimately possesses),
- but `repository.full_name` = `"org-b/victim-repo"`, a stack belonging to a different organization entirely.

`verify_signature` succeeds (org A's secret validates), yet `PushHandler`/`Handler#stacks` resolves and mutates `Stack`s under `org-b`'s repository via `Repository.from_github_repo_name(repository_name)`. This breaks the equality that should hold: `organization whose secret authenticated the request == owner of the repository the handler is about to act on`.

### Impact Explanation
For the `push` event this lets an attacker (who only administers their own, unrelated organization's GitHub App connected to this shared Shipit instance) forge a "push" notification for a victim stack they do not own, forcing `GithubSyncJob` to run for that victim stack: [4](#0-3) 

If the victim stack has continuous deployment enabled, this out-of-band sync can trigger deploy logic without any authentic signal from the victim organization — an unauthorized deploy triggered purely by cross-tenant signature confusion, which matches the "unauthorized deploy" Critical impact bucket in scope. Even where CD isn't enabled, this still lets an unrelated org's credential arbitrarily force stack refresh/commit ingestion cycles on a stack it doesn't administer, i.e., cross-repository writes performed under a signature that was never actually issued or endorsed by the target organization's GitHub App installation.

### Likelihood Explanation
Exploitation only requires that the attacker legitimately control the webhook secret of *any single* organization onboarded to the shared Shipit instance (a realistic, unprivileged position in any multi-tenant Shipit deployment, since organizations self-manage their own GitHub App webhook secret) and knowledge of a target stack's `repo_owner/repo_name` (which is public information visible via the Shipit UI/API for stacks that are not access-restricted). No `GITHUB_TOKEN`, `api_clients_secret`, or Shipit session is needed — only the ability to send a raw HTTP POST to the public `/webhooks` endpoint with a correctly-computed HMAC using their own org's secret.

### Recommendation
Do not let the payload itself choose which secret validates it. Bind webhook authentication to a value that is independently trustworthy — e.g., verify against the secret of the specific `GithubHook`/installation the request claims to come from (using the `X-GitHub-Hook-Installation-Target-ID`/App installation identity from the request context rather than JSON body fields), or verify the signature against every configured organization's secret and then require that the `repository.full_name` owner match exactly the organization whose secret validated the payload before dispatching to handlers.

### Proof of Concept
Not directly runnable without two configured Shipit organizations and their webhook secrets, but conceptually:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(org_a_secret, body)>

{
  "ref": "refs/heads/main",
  "after": "<victim's real head sha>",
  "repository": {
    "owner": { "login": "org-a" },        # matches attacker's own secret -> passes verify_signature
    "full_name": "org-b/victim-repo"       # actually resolved by PushHandler to sync org-b's stack
  }
}
```
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` succeeds because `repository_owner` (`"org-a"`) matches the secret used to compute the signature, while `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) resolves the stack via `repository.full_name` (`"org-b/victim-repo"`), triggering `GithubSyncJob` for a stack the attacker does not control.

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
