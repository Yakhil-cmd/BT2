### Title
Webhook signature verification binds only the claimed organization, not the actual repository/commit acted on, allowing cross-repository status/sync forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The Audius report describes a proxy where the documented "governance controls upgrades" invariant is broken because one privileged entry point (`upgradeTo`) enforces the binding while a sibling entry point (`upgradeToAndCall`) does not, letting the admin bypass governance. The analogous binding in Shipit is: *the GitHub organization whose webhook secret validated the signature* should equal *the repository/commit that the handler actually mutates*. `WebhooksController` only authenticates the claimed **organization** name from the payload, while the actual event handlers (`Shipit::Webhooks::Handlers::Handler`, `StatusHandler`, `PushHandler`) act on a **repository full name** or a bare **commit SHA** taken from the same unauthenticated payload, with no check that these fields belong to the organization whose secret was used.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/secret to verify against using only the organization login pulled out of the untrusted JSON body: [1](#0-0) [2](#0-1) 

Once the HMAC is confirmed to match the secret configured for that `repository_owner`, the raw payload is handed to `Shipit::Webhooks.for_event(event)` handlers verbatim — the signature only proves "someone who knows organization X's webhook secret sent this," it says nothing about which repository/commit the payload's other fields legitimately reference.

Downstream, the base `Handler` resolves the target purely from the unauthenticated `repository.full_name` field: [3](#0-2) 

`PushHandler` uses that scope to trigger `GithubSyncJob` on the resolved stack: [4](#0-3) 

`StatusHandler` is even weaker — it doesn't scope by repository at all, only by a raw commit SHA, and directly writes a `CommitStatus` record for whichever commit(s) match: [5](#0-4) 

Multi-tenant Shipit deployments configure a distinct GitHub App/`webhook_secret` per organization, as shown in the sample config listing several independent orgs each with their own credentials: [6](#0-5) 

The equality that should hold is: **organization authenticated by the HMAC == organization that owns the repository/commit the handler mutates**. Nothing in the code enforces this. An entity that legitimately administers *any* one organization onboarded to the Shipit instance (and therefore knows/controls that org's own webhook secret, since org admins configure their own GitHub App) can craft a `status` (or `push`) webhook payload whose `repository.owner.login`/`organization.login` is their own org (so it passes `verify_signature`), while setting `repository.full_name` to an unrelated repository, or simply putting an arbitrary victim commit `sha` in the body. Because `StatusHandler` looks up commits by SHA across the whole database with no repository check, this is sufficient to inject a forged `CommitStatus` (e.g., a fake "success" for CI/required checks) onto any tracked commit belonging to a completely different, higher-privilege repository/stack.

### Impact Explanation
Forged commit statuses feed deploy eligibility (`Stack` deploy conditions consult `CommitStatus`/`Status::Group`), so an attacker who only controls a low-privilege organization entry in the multi-tenant config can flip required checks to green on a victim's high-value stack and unblock an unauthorized deploy — this satisfies the Critical "unauthorized deploy" bar. At minimum it allows unauthenticated-write cross-repository/cross-organization forgery of stack sync and commit-status state, which is the "cross-repository writes" criterion.

### Likelihood Explanation
Any organization/App entry configured on a shared/multi-tenant Shipit instance is, by design, a distinct trust boundary from every other org's repositories. The webhook path never re-checks that the payload's repository/commit fields correspond to the org that produced the valid signature, so exploitation only requires the attacker to control one legitimate, low-privilege org already integrated with the instance and to craft one JSON payload — no additional secrets, tokens, or social engineering needed beyond what the rules already require ("unprivileged attacker" who has access to at least one configured org's own webhook secret, which they legitimately possess as that org's administrator).

### Recommendation
Bind the verified signature to the acted-upon resource: after computing the signing organization, require that `repository.owner.login` used for signature verification match `repository.full_name`'s owner used by the handler, and reject/short-circuit `StatusHandler` (and any other handler) unless the resolved `Commit`/`Stack`/`Repository` actually belongs to the organization that signed the request.

### Proof of Concept
1. Attacker legitimately administers organization `attacker-org`, which is configured in Shipit with its own `webhook_secret` (`config/secrets...yml` pattern).
2. Attacker computes a valid `X-Hub-Signature` for a `status` event JSON body using `attacker-org`'s known secret, per `Hook::DeliverySigner`/`GithubApp#verify_webhook_signature` logic (`lib/shipit/github_app.rb:76-83`).
3. Body sets `repository.owner.login` = `attacker-org` (passes `verify_signature`, see `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`), but `sha` = the SHA of a commit that actually belongs to `victim-org/victim-repo`, and `state` = `success`.
4. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches the commit purely by `sha`, with no ownership check, and writes a forged success status onto the victim's commit, potentially unblocking its deploy.

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
