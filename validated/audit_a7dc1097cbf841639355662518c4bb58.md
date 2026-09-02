## Confirmed

This is a valid analog: the signature is verified against an organization selected from an **unverified** field in the JSON payload (`repository.owner.login` / `organization.login`), while the actual repository/stack that gets acted upon is selected from a **different, independently unverified** field (`repository.full_name`). In a multi-organization Shipit deployment these two fields are not bound together by the signature, so a party who only knows one organization's `webhook_secret` can forge events attributed to a repository belonging to a different, victim organization.

### Title
Webhook signature is verified against an organization chosen from an unsigned field while the acted-upon repository comes from a different unsigned field, enabling cross-organization event forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App config (and thus which `webhook_secret`) to verify the HMAC signature against by reading `repository.owner.login` (falling back to `organization.login`) straight out of the still-unauthenticated JSON body. Once the signature check passes, `create` dispatches the very same raw payload to handlers such as `PushHandler`, which locate the target `Repository`/`Stack` using a completely different payload field: `repository.full_name`. Nothing binds the organization used for signature verification to the repository that is ultimately written to.

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and uses it to fetch the GitHub App config via `Shipit.github(organization: repository_owner)`, then checks the request HMAC against that config's `webhook_secret`: [1](#0-0) [2](#0-1) 

Once verification passes, the full (attacker-supplied) payload is handed unmodified to every registered handler for the event: [3](#0-2) 

Handlers such as `PushHandler` resolve the target repository/stack from a *different* field, `repository.full_name`, via `Handler#repository_name` / `Handler#stacks`: [4](#0-3) [5](#0-4) 

`Shipit.github(organization:)` explicitly supports per-organization config in multi-org deployments, each with its own `webhook_secret`: [6](#0-5) [7](#0-6) 

**Binding broken (equality that must hold but doesn't):**
`organization_used_for_signature_verification == organization_owning(repository_used_by_handlers)`

Before the fix (i.e., as coded today): the controller reads `repository.owner.login`/`organization.login` to select the verifying secret, but `PushHandler` (and other handlers) independently read `repository.full_name` to select the stack to act on. Since neither the JSON parser nor the HMAC check ties these two fields together, an attacker can set `organization.login` (or `repository.owner.login`) to an organization whose `webhook_secret` they know, sign the payload with that secret, but set `repository.full_name` to a repository belonging to a *different* organization configured on the same Shipit instance. The signature check passes (correct secret for the org named in that field), yet the handler acts on the unrelated repository named in `repository.full_name`.

After a correct fix, the same field used to select the verifying key would also be validated/derived consistently with the field the handler acts on (e.g., derive `repository_owner` strictly from `repository.full_name`, or reject payloads where `organization.login` and `repository.owner.login` disagree with `repository.full_name`'s owner).

### Impact Explanation
On a multi-organization Shipit install (the supported config pattern shown in `test/dummy/config/secrets_double_github_app.yml`), an entity that only controls webhook delivery for Organization A (and thus knows Organization A's `webhook_secret`) can forge a `push` (or other) event that is verified using Organization A's secret but whose `repository.full_name` points at a stack belonging to Organization B. `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on Organization B's stack — an unauthorized cross-repository/cross-organization action triggered without ever proving the secret belonging to Organization B. This is a cross-repository-write class issue: it lets an attacker who is authenticated for one repository/org write/trigger sync on another org's stack.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (documented, first-class supported configuration), and (2) knowledge of one organization's `webhook_secret` (obtainable by anyone with access to that org's GitHub App webhook settings — not the victim org). No GitHub App private key, no `ApiClient` token, and no privileged Shipit account are needed; only a webhook secret for *any* configured organization on the instance. This is a realistic scenario for shared/hosted multi-tenant Shipit instances.

### Recommendation
Bind the organization used for signature verification to the same field(s) the handlers use to select the target repository. Concretely, derive `repository_owner` in `WebhooksController#verify_signature` from `repository.full_name`'s owner segment (the same source `Handler#repository_name` uses), or verify that `repository.owner.login`/`organization.login` match the owner segment of `repository.full_name` before proceeding, rejecting the request otherwise.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As someone who knows `OrgA`'s `webhook_secret` (e.g. an OrgA member with webhook config access, not affiliated with OrgB), craft a `push` event payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
   }
   ```
3. Compute `X-Hub-Signature` as `sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` to `"OrgA"` (from `repository.owner.login`) and validates successfully against `OrgA`'s secret via `verify_webhook_signature` in `lib/shipit/github_app.rb`.
6. `create` dispatches to `PushHandler`, whose `repository_name` reads `repository.full_name` = `"OrgB/victim-repo"`, locating and triggering `sync_github` on OrgB's stack — despite the request never being authenticated with any secret belonging to OrgB.

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-9)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
```
