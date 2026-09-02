## Analog Found: Webhook signature verified against `repository.owner.login`, but the acted-upon repository is taken from the unbound `repository.full_name` field

### Title
Webhook Org/Repo Binding Confusion Allows Cross-Tenant Webhook Forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
The bug class in the Pico report is a **binding mismatch**: `read_ghost_addr` calls a shared internal method with a parameter that is inconsistent with its sibling ghost-read methods, so the value it modifies (multiplicity) is decoupled from the value that was actually verified/intended. The same class of bug exists in Shipit's webhook pipeline: the field used to select *which secret authenticates* the request (`repository.owner.login` / `organization.login`) is not the same field used to select *which repository/stack the payload acts on* (`repository.full_name`). Nothing enforces that these two fields refer to the same GitHub organization.

### Finding Description
`Shipit::WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret` used for HMAC verification) using `repository_owner`: [1](#0-0) [2](#0-1) 

Once the signature is accepted, the controller dispatches the **entire raw payload** to every registered handler for the event, unmodified: [3](#0-2) 

Each handler then determines which `Stack`/`Repository` the event applies to using a *different* field, `repository.full_name`, via `Handler#repository_name` / `Handler#stacks`: [4](#0-3) 

Nothing ties `repository.full_name`'s owner segment back to `repository_owner` (the value that was actually authenticated). In a multi-tenant Shipit deployment — which is an explicitly supported configuration, as shown by the multi-org secrets fixture — each GitHub organization has its own `GitHubApp` entry and its own `webhook_secret`: [5](#0-4) 

The equality the code implicitly assumes but never enforces is:
`organization that authenticated the request == owner(repository.full_name) that the handler writes to`

An attacker who controls (or has push access sufficient to trigger real webhooks for) one onboarded, low-trust GitHub organization "OrgA" knows or can derive OrgA's `webhook_secret` (it is configured by whoever administers OrgA's GitHub App, not by the Shipit operator on a per-request basis). They can then send a POST directly to `/github/webhooks` (bypassing GitHub entirely) with:
- `repository.owner.login = "OrgA"` (or `organization.login = "OrgA"`) so `verify_signature` selects OrgA's `GitHubApp` and the HMAC computed with OrgA's secret validates,
- `repository.full_name = "OrgB/victim-repo"` — a completely different, higher-trust organization's repository that also has a stack configured in the same Shipit instance.

Because `verify_signature` and `Handler#repository_name` consult different fields of the same attacker-controlled JSON body, the signature check provides no actual guarantee about which repository's stacks get mutated. This is directly analogous to `read_ghost_addr` calling `read_addr_internal(addr, true)` while its sibling `read_ghost_vaddr` uses `false` — a value that is supposed to move in lock-step with a sibling/verified value diverges because of an inconsistent field/parameter choice.

### Impact Explanation
Depending on which handler fires, this reaches into `PushHandler` (queues `GithubSyncJob` for the target stack, i.e. force resync of a stack that is not related to the org that authenticated), `StatusHandler` (writes fabricated commit statuses that CI-gating and merge-queue logic rely on to decide whether to deploy/merge), and `PullRequest::OpenedHandler` (provisions review stacks). Forged commit statuses can flip `commit.deployable?` for an unrelated stack, and forged push events can force `GithubSyncJob` to run against a victim's stack — this is a cross-repository write of state that a Shipit operator would reasonably assume is protected by per-organization webhook signing. It does not directly grant `GITHUB_TOKEN` exfiltration or RCE, but it is an unauthorized, cross-tenant mutation of another organization's Stack/Commit/Status records driven purely by attacker-supplied JSON once one tenant's webhook secret is known to that tenant — satisfying the "cross-repository writes" bar.

### Likelihood Explanation
Requires: (1) a Shipit instance configured for multiple GitHub organizations (a documented, supported setup), and (2) the attacker being the administrator/possessor of the `webhook_secret` for any one of the onboarded low-privilege organizations — not the target organization's secret, and not GitHub App private keys or Shipit `ApiClient` tokens. This is a materially different, weaker prerequisite than compromising the target org, which is what makes it a genuine trust-boundary violation rather than "attacker already owns the target."

### Recommendation
In `Shipit::WebhooksController#verify_signature` and/or `Shipit::Webhooks::Handlers::Handler`, enforce that the organization used to select the verifying `GitHubApp`/secret (`repository_owner`) matches the owner segment of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers; reject the payload with `422` otherwise.

### Proof of Concept
Not executed against a live instance; based on static code review of `app/controllers/shipit/webhooks_controller.rb` and `app/models/shipit/webhooks/handlers/handler.rb`. Conceptually: POST to `/github/webhooks` with header `X-Github-Event: push`, `X-Hub-Signature` computed as `sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)`, and body `{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen sha>"}` — `verify_signature` passes because it only inspects `repository.owner.login`, and `PushHandler` will resolve `Repository.from_github_repo_name("OrgB/victim-repo")` and enqueue a `GithubSyncJob` for that stack.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
