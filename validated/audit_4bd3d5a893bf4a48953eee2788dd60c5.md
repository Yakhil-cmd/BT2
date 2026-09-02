## Title
Webhook signature verified against attacker-chosen organization while handlers act on an unauthenticated `repository.full_name` field — cross-repository / cross-organization write via signature-org / repository-name mismatch (`app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC against based on `repository_owner`, a value read from the *unauthenticated* JSON body (`params.dig('repository','owner','login')`). Once the HMAC passes with that secret, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` hands the *entire* raw payload to handlers such as `PushHandler`/`StatusHandler`, which resolve the target `Stack`/`Repository` using a *different* field of the same payload: `payload.dig('repository', 'full_name')` (`Handler#repository_name`, `app/models/shipit/webhooks/handlers/handler.rb:36-38`). Nothing ties `repository.owner.login` (used to pick the secret) to `repository.full_name` (used to pick the stack that gets written to).

### Finding Description
The binding that should hold is:
`organization whose webhook_secret authenticated the signature == organization owning the repository whose stacks get mutated by the handler`

In a multi-org Shipit deployment, `Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization (`lib/shipit.rb:170-181`, `test/dummy/config/secrets_double_github_app.yml`). `WebhooksController#verify_signature` computes which secret to use from the payload itself: [1](#0-0) [2](#0-1) 

Once `verify_webhook_signature` succeeds (HMAC-SHA1 over the raw body using the secret for that *claimed* owner), the controller dispatches the full parsed payload to handlers: [3](#0-2) 

The handlers, however, don't reuse `repository_owner`; they independently derive the target repository from `repository.full_name`: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` then splits `full_name` on `/` and looks up by `owner`/`name` columns with no relationship to which org's secret verified the request: [6](#0-5) 

An attacker who knows (or has legitimately been given, e.g. as a repo admin on one tracked org's GitHub App/webhook config) the `webhook_secret` for OrgA can craft a payload where `repository.owner.login` = `OrgA` (so `verify_signature` selects and validates against OrgA's secret) but `repository.full_name` = `OrgB/some-repo` (a repository belonging to a completely different organization tracked by the same Shipit instance). The HMAC is computed over the raw JSON body containing the mismatched `full_name`, so as long as it's signed with OrgA's secret it passes `verify_signature`, and the handler will then act on `OrgB/some-repo`'s stacks — e.g. triggering `sync_github` (`PushHandler`) or writing commit statuses (`StatusHandler`) for a repository the attacker's credential was never scoped to.

### Impact Explanation
This breaks the trust boundary between organizations in a multi-org deployment: possession of one organization's webhook secret is sufficient to forge webhook events (`push`, `status`, `check_suite`, `membership`, etc.) targeting *any other organization's repositories* configured on the same Shipit instance, because the org used for signature verification is never reconciled with the org embedded in the mutated `repository.full_name`. Depending on which handler is targeted, this can force out-of-band syncs, corrupt commit CI statuses (`StatusHandler` → `Commit#create_status_from_github!`), or create arbitrary teams/users (`membership` event, per `test/controllers/webhooks_controller_test.rb:129-149`) attributed to a different organization's namespace — a cross-repository/cross-organization write performed by an actor authorized only for a different repository/org.

### Likelihood Explanation
Requires the attacker to already control a valid webhook secret for at least one organization tracked by the Shipit instance (e.g. as a legitimate GitHub App admin/webhook operator for that one org), and requires the target instance to be configured with multiple GitHub organizations (the multi-org secrets schema demonstrated in `test/dummy/config/secrets_double_github_app.yml`). This is a real, low-effort forgery (just craft a JSON body and HMAC-sign it with a secret the attacker legitimately possesses) rather than a cryptographic break, but it depends on the multi-org deployment configuration and on the attacker having at least one org's secret — a bounded, but externally-plausible, precondition, analogous to the "big but eventually reachable" precondition in the original report.

### Recommendation
After signature verification, re-derive `repository_owner` (or `full_name`'s owner) strictly from the *same* value used to select the verifying secret, and reject the request (or re-verify) if `payload.dig('repository','full_name')`'s owner does not case-insensitively match `repository_owner`/the organization whose secret validated the signature. Alternatively, pass `repository_owner` down to `Handler` and have `Handler#stacks` filter/validate against it instead of trusting `full_name` in isolation.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Craft a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac>` over the raw body using OrgA's `webhook_secret` (known to the attacker).
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `repository_owner` = `OrgA`, verifies successfully against OrgA's secret (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`).
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name('OrgB/target-repo')` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) and triggers `stack.sync_github(expected_head_sha:)` for OrgB's stack — a write performed on OrgB's repository despite being signed only by OrgA's secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
