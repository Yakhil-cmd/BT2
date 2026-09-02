### Title
Multi-organization webhook secret selection lets any onboarded organization forge status/push events for repositories belonging to a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate an incoming webhook against using a field taken from the *payload itself* (`repository.owner.login`, falling back to `organization.login`), rather than from any binding tied to the specific repository the event ultimately acts on. Handlers such as `StatusHandler` and `PushHandler` then process the same payload using a different field (`sha`, or `repository.full_name`) to decide which `Commit`/`Stack` to mutate. In a Shipit deployment configured for multiple GitHub organizations (a documented, supported configuration in `docs/setup.md`), this creates a mismatch: the org whose secret authenticated the request is not cryptographically bound to the repository/commit the handler writes to.

### Finding Description
`WebhooksController#verify_signature` picks the app config like this: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` looks up a *per-organization* `webhook_secret` (as configured under `config/secrets.yml`'s multi-org `github:` block, documented in `docs/setup.md` "Using Multiple Github Applications"). The signature is an HMAC over the raw JSON body, so it does cryptographically bind the *entire payload bytes* to whichever secret was selected - but the secret selection itself is attacker-influenced (it comes from `repository.owner.login` inside the very payload being signed), and each organization onboarded into the shared Shipit instance holds its *own* distinct secret.

Once `verify_signature` passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full payload to handlers that key their side effects off of entirely different payload fields:

- `StatusHandler#process` matches purely on `sha`, with **no repository check at all**: [3](#0-2) 

- `PushHandler#process` resolves target stacks via `Handler#repository_name`, i.e. `payload.dig('repository', 'full_name')`: [4](#0-3) [5](#0-4) 

The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization/repository the handler actually writes state for`

In this engine that equality does not hold, because:
1. The org used for `verify_webhook_signature` is read from `repository.owner.login`/`organization.login` in the same JSON body the attacker fully controls and signs.
2. `StatusHandler` does not check the `repository` field of the payload at all - it applies `create_status_from_github!` to *any* `Commit` row in the database whose `sha` matches, regardless of which stack/org owns that commit.
3. `PushHandler` derives the target `Repository`/`Stack` from `repository.full_name`, a field independent of, and unconstrained relative to, `repository.owner.login` used for secret selection.

Concretely: an org "OrgA" that has legitimately onboarded its own GitHub App into a shared Shipit instance (and therefore knows OrgA's `webhook_secret`, per `lib/shipit/github_app.rb`'s `verify_webhook_signature`) can craft a webhook payload where:
- `repository.owner.login = "OrgA"` (so `verify_signature` selects and validates against OrgA's own secret - which the attacker legitimately possesses),
- `sha` = a known commit SHA belonging to a stack owned by "OrgB" (a different, unrelated organization/tenant of the same Shipit instance), or `repository.full_name` = `"OrgB/target-repo"`.

Because the HMAC only proves "this exact byte sequence was signed by whoever holds OrgA's secret," and OrgA's secret is legitimately known to OrgA's own admins, the signature check passes even though the payload's *acted-upon* fields (`sha`, `repository.full_name`) reference OrgB's data. `StatusHandler` will happily call `Commit.where(sha: params.sha)` and inject a forged CI status (e.g., `state: "success"`) onto OrgB's commit, or `PushHandler` will trigger a sync against OrgB's repository/stack, all authenticated only by OrgA's own secret.

### Impact Explanation
Forging a `status` event for a commit belonging to a different organization's stack directly manipulates `Commit#create_status_from_github!` / `Status::Group`, which feeds `MergeRequest#any_status_checks_failed?` / `#any_status_checks_missing?` used by the merge queue (`app/models/shipit/merge_request.rb`) and by `Commit#deployable?`. A forged "success" status can make a pull request appear CI-green and eligible for auto-merge (`MergeRequest#merge!`) or make a commit `deployable?` for continuous deployment in a stack/organization the attacker does not control - i.e., an unauthorized merge or deploy triggered against a cross-tenant repository, and a cross-repository/cross-tenant write of state (`Status` records) the attacker has no legitimate access to. This matches the "cross-repository writes" / "unauthorized deploy, rollback or merge" High/Critical impact class.

### Likelihood Explanation
Requires the multi-organization GitHub App configuration described in `docs/setup.md` ("Using Multiple Github Applications") to be in use, and requires the attacker to control at least one organization/tenant onboarded into the shared Shipit instance (and thus legitimately know that org's own `webhook_secret`). The attacker also needs to know or guess a target commit SHA (often discoverable via public commit history) or a target `repository.full_name`. No GitHub App private key, `api_clients_secret`, or `ApiClient` token is needed - only the ability to POST an arbitrary signed webhook body to `/webhooks`, which is an unauthenticated public endpoint (`skip_before_action :verify_authenticity_token`, no session required). This is plausible in any deployment that supports multiple tenants/organizations sharing one Shipit instance, which the engine explicitly documents as a supported topology.

### Recommendation
Do not select the verification secret from attacker-controlled payload fields alone; instead, bind the verified organization to the specific repository/stack a handler is permitted to mutate. Concretely:
- In `Handler#stacks`/`Handler#repository_name` (and in `StatusHandler#process`), verify that the resolved `Stack`'s `repository.owner` matches the organization whose secret validated the signature (pass the verified organization through from `WebhooksController` into the handler dispatch and assert equality before applying any mutation).
- For `StatusHandler`, restrict `Commit.where(sha: params.sha)` to commits whose `stack.repository.owner` equals the verified organization, rather than matching bare SHA across all tenants.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per the documented multi-org `config/secrets.yml` layout).
2. As an administrator of `OrgA` (attacker), legitimately obtain `OrgA`'s `webhook_secret`.
3. Identify a commit SHA `victim_sha` belonging to a `Stack` owned by `OrgB` (e.g., from OrgB's public commit history).
4. Craft a JSON body:
   ```json
   {
     "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/attacker-repo"},
     "sha": "victim_sha",
     "state": "success",
     "context": "ci/forced",
     "branches": [{"name": "master"}]
   }
   ```
5. Compute `X-Hub-Signature: sha1=<hmac>` using `OrgA`'s `webhook_secret` over the exact raw body, and set `X-Github-Event: status`.
6. POST to `/webhooks`. `WebhooksController#verify_signature` selects `OrgA`'s secret via `repository_owner` and validates successfully.
7. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which executes `Commit.where(sha: 'victim_sha').each { |commit| commit.create_status_from_github!(params) }`, writing a forged "success" status onto `OrgB`'s commit despite the request being authenticated solely with `OrgA`'s credentials.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
