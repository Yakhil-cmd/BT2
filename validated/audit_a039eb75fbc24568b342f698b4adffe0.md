### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login`, not to the `repository.full_name` that handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to check the `X-Hub-Signature` HMAC based on `repository.owner.login` (falling back to `organization.login`) taken from the untrusted JSON body, while every `Handler` resolves the actual `Repository`/`Stack` to mutate using a *different* field of the same untrusted body, `repository.full_name`. Nothing binds these two fields together, so a signature that is valid for organization A's webhook secret does not guarantee the payload's `repository.full_name` actually belongs to organization A.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and fetches the corresponding `GitHubApp` config purely by that string: [1](#0-0) [2](#0-1) 

The signature is checked with `GitHubApp#verify_webhook_signature`, which is a plain HMAC-SHA1 comparison against that organization's configured `webhook_secret`: [3](#0-2) 

Once the signature passes, the raw JSON body is dispatched unmodified to the registered handler(s): [4](#0-3) 

Every handler (e.g. `PushHandler`, `StatusHandler`, the `pull_request` handlers) resolves the stacks/repository to act on via `Handler#stacks`, which reads a *separate* JSON key, `repository.full_name`: [5](#0-4) [6](#0-5) 

The equality that Shipit's authentication model implicitly assumes is:

`organization that authenticated the request (repository.owner.login / organization.login)` == `repository whose stacks/commits get mutated (repository.full_name)`

Nothing in `verify_signature` or in `Handler#initialize`/`Handler#stacks` enforces this equality — the two fields are read independently from the same attacker-supplied JSON body and never cross-checked. In a multi-organization Shipit deployment (the engine explicitly supports configuring several GitHub Apps, each with its own `webhook_secret`, see `config/secrets.development.shopify.yml` and `lib/shipit.rb`'s `Shipit.github(organization:)` lookup used by `verify_signature`), an entity that legitimately controls one onboarded organization's GitHub App webhook secret can forge a request whose `X-Hub-Signature` is valid for its own organization while `repository.full_name` names a stack belonging to a *different* onboarded organization.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out as in-scope. Concretely, with a valid signature computed from Organization A's own webhook secret but `repository.full_name` set to `"OrgB/private-repo"`:
- `PushHandler` will call `stack.sync_github(expected_head_sha:)` on OrgB's stacks, forcing an out-of-band sync/deploy trigger for a repository the attacker does not control.
- `StatusHandler` will create a `Status` on OrgB's commits from forged `state`/`context`/`description`/`target_url` fields, which can be used to fake a passing CI status on a commit that has not actually passed CI (`Commit#create_status_from_github!`), directly enabling an **unauthorized deploy** if OrgB's stack uses continuous deployment gated on required statuses.
- Other handlers keyed the same way (`pull_request/*`) can similarly act cross-organization.

This matches the "unauthorized deploy" Critical impact criterion, achieved without any Shipit session, `ApiClient` token, or GitHub write access to the victim organization — only knowledge of a webhook secret belonging to a different, unrelated organization that is also onboarded onto the same Shipit instance.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where more than one GitHub organization/App is configured (explicitly supported and documented, e.g. `config/secrets.development.shopify.yml`, `docs/setup.md`'s per-organization `github:` block). Any entity that administers one such onboarded GitHub App (and thus legitimately knows its `webhook_secret`) can exploit this without needing any credentials belonging to the target organization. This is a realistic configuration for shared/hosted Shipit instances serving multiple orgs/customers.

### Recommendation
After signature verification succeeds for organization X, verify that `repository.full_name` (and any other repository-identifying field consumed by handlers) actually belongs to organization X — e.g., assert `payload.dig('repository', 'full_name').to_s.split('/').first.casecmp?(repository_owner)` before dispatching to handlers, or have handlers resolve stacks scoped by the authenticated organization rather than trusting `repository.full_name` alone.

### Proof of Concept
1. Shipit is configured with two organizations, `orga` and `orgb`, each with its own GitHub App and `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. Attacker administers `orga`'s GitHub App and therefore knows `orga`'s `webhook_secret`.
3. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orga_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"orga"`, fetches `orga`'s `GitHubApp`, and the HMAC check passes (attacker signed with the correct secret for `orga`).
6. `PushHandler#process` runs `Repository.from_github_repo_name("orgb/victim-repo")`, finds `orgb`'s stacks, and triggers `stack.sync_github(expected_head_sha: <attacker sha>)` — a cross-organization action the attacker was never authorized to perform on `orgb`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
