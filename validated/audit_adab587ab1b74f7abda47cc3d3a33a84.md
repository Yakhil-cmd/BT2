### Title
Webhook signature verification is bound to the wrong field, allowing any onboarded organization to forge events for another organization's repositories - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App/organization derived from one JSON field, while the handlers that act on that payload derive the target repository from a *different, independently-readable* JSON field in the same attacker-controlled body. Because the two fields are never checked against each other, a party who legitimately controls the webhook secret for organization A can forge a signed payload that authenticates as organization A but names a repository belonging to organization B, causing Shipit to act on organization B's stacks.

### Finding Description
The signature check resolves the signing organization like this: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) and is used only to pick which per-organization `webhook_secret` to verify the HMAC against, via `Shipit.github(organization: repository_owner)`.

Once the signature is accepted, the raw JSON `params` is dispatched unchanged to the registered handler: [3](#0-2) 

Handlers, however, resolve the actual target repository/stacks from a *different* field of the same untrusted payload: [4](#0-3) 

`Repository.from_github_repo_name` looks the repository up purely from `repository.full_name`: [5](#0-4) 

Nothing enforces that `repository.owner.login` (used for authentication) matches `repository.full_name`'s owner segment (used for authorization). Since the controller does `JSON.parse(request.raw_post)` on an attacker-suppliable HTTP body, an attacker who knows *any* valid per-organization `webhook_secret` configured in this Shipit instance (e.g. because they legitimately administer their own onboarded organization/repository) can hand-craft a raw body such as:

```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```

sign it with `attacker-org`'s known secret, and POST it directly (bypassing GitHub entirely). `verify_signature` authenticates against `attacker-org` and passes, but `PushHandler` (and any other handler keying off `repository.full_name`, e.g. `StatusHandler`, `CheckSuiteHandler`) will resolve and mutate `victim-org/victim-repo`'s stacks: [6](#0-5) 

This is exactly the class of bug described in the report — user-controlled input (here, the `repository` object of a webhook payload) is trusted for two purposes that should be cryptographically bound together but are validated independently, letting attacker-controlled data "leak" past a trust boundary (the per-organization signing boundary) and be acted upon as if it belonged to a different, unauthenticated principal (a foreign repository/organization).

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written," which is explicitly in-scope. The forged `push` event forces `stack.sync_github(expected_head_sha: ...)` to run against a stack the attacker does not control, on a repository the attacker has no access to. Depending on stack configuration (e.g. continuous deployment enabled), this resync can seed the stack's known commits/HEAD tracking with an attacker-chosen SHA, and other handlers reachable the same way (`StatusHandler`, `CheckSuiteHandler`) can inject fabricated CI status/check-run state for the victim repository's commits, which Shipit's merge/deploy safety checks rely on. This can result in an unauthorized deploy or merge decision being influenced by attacker-forged signals — meeting the High/Critical bar ("escalation into authorization" / "unauthorized deploy or merge").

### Likelihood Explanation
Requires the attacker to have legitimate access to at least one organization's `webhook_secret` already configured in the multi-tenant Shipit deployment (i.e., they are a legitimate but separate tenant/user of the same Shipit instance) — no GitHub App private key, `api_clients_secret`, or victim credentials are needed. This is a realistic scenario for any Shipit deployment onboarding multiple independent GitHub organizations.

### Recommendation
Bind the field used for authentication to the field used for authorization: after verifying the signature, re-derive `repository_owner`/`repository_name` from the exact same sub-object, and additionally verify (in `Handler#stacks` or centrally in `WebhooksController`) that the resolved `Repository#owner` matches the organization whose secret authenticated the request. Reject the webhook if they diverge.

### Proof of Concept
1. Attacker has legitimate access to Shipit-configured organization `attacker-org` (knows its `webhook_secret`).
2. Attacker crafts raw JSON body:
```json
{"repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"},"ref":"refs/heads/main","after":"<sha>"}
```
3. Computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>`.
4. POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` succeeds (authenticates as `attacker-org`).
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "<sha>")` on stacks the attacker does not own.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
