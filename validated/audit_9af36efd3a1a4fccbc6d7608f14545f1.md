### Title
Webhook signature is validated against the organization derived from `repository.owner.login`, but event handlers act on a completely different, unscoped identifier — allowing cross-repository status forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to validate a webhook's HMAC against based on the `repository.owner.login` (or `organization.login`) field of the attacker-supplied JSON body. Once the signature check passes, the event is dispatched to a handler, but several handlers do not re-validate that the payload's target actually belongs to the organization that was authenticated. `StatusHandler` in particular ignores the repository entirely and matches purely by commit `sha`, globally across every stack hosted by the Shipit instance.

### Finding Description
`verify_signature` selects the GitHub App config to check the signature with: [1](#0-0) [2](#0-1) 

The organization used to select the secret (`repository_owner`) is read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). Because the whole raw request body is attacker-controlled when POSTing directly to the public `/webhooks` endpoint, and Shipit is designed to host many organizations/repositories behind a single instance (`Shipit.github(organization: repository_owner)` looks up per-organization config, raising `GithubOrganizationUnknown` if not configured), any organization administrator legitimately configured in Shipit knows *their own* webhook secret and can produce a validly-signed request.

Once verification passes, the event is routed to a handler: [3](#0-2) 

`StatusHandler` processes the `status` event by matching commits purely by SHA, with **no** scoping to the repository or organization that was authenticated: [4](#0-3) 

This breaks the binding: `repository.owner.login` (the identity whose secret authenticated the request) ≠ the repository/stack that is actually written (any stack in the entire installation whose commit table happens to contain a matching `sha`). The base `Handler` class does scope other handlers via `repository.full_name`: [5](#0-4) 
but `StatusHandler` (unlike `PushHandler`/`CheckSuiteHandler`) never calls `stacks`, so this scoping is bypassed entirely for status events.

### Impact Explanation
An organization admin who is a legitimate (unprivileged with respect to *other* organizations) Shipit tenant can forge a `status` webhook, signed with their own org's webhook secret, that targets a commit SHA belonging to a stack in a completely different, unrelated organization/repository hosted on the same Shipit instance. Via `Commit#create_status_from_github!`, this injects an arbitrary CommitStatus (e.g., marking a required CI context as `success`) on a commit they do not own. If that context is part of the target stack's `ci.require` list, this can satisfy Shipit's deploy-gating checks and enable an **unauthorized deploy** on a repository the attacker has no legitimate access to — a cross-tenant/cross-repository write that meets the Critical impact bar ("unauthorized deploy").

### Likelihood Explanation
Exploitability only requires: (1) the Shipit instance hosts more than one organization (a documented, supported multi-tenant configuration), (2) the attacker administers one of those organizations and therefore legitimately knows its webhook secret, and (3) the target commit SHA is discoverable (commit SHAs from public GitHub repositories are trivially known). No compromise of Shipit's own credentials, no session, and no `ApiClient` token are required — only the ability to sign a POST body with a secret the attacker legitimately possesses for their own tenant. This is a straightforward, repeatable path.

### Recommendation
Scope every webhook handler — especially `StatusHandler` — to the repository/organization that was actually authenticated during signature verification, not merely to attacker-supplied identifiers embedded in the payload. Concretely: thread the `repository_owner`/`repository.full_name` used during `verify_signature` through to handler dispatch, and have `StatusHandler#process` restrict its `Commit` lookup to commits belonging to stacks of that specific repository (mirroring the `stacks` helper in `Handler`), rejecting or ignoring events whose payload repository does not match the authenticated organization.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, configured as a tenant on the shared Shipit instance, and knows `attacker-org`'s webhook secret.
2. Attacker crafts a JSON body for a `status` event:
```json
{
  "sha": "<known commit sha from victim-org/victim-repo, part of a required CI context>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example.com",
  "description": "forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s GitHub App config, and successfully verifies the signature.
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the commit in `victim-org/victim-repo` — and calls `create_status_from_github!`, injecting a forged "success" status on a commit outside the attacker's organization, potentially unblocking a deploy gated on that CI context.

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
