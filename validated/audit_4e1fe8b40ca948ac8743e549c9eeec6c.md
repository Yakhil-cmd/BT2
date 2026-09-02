## Analysis

This confirms the trust binding break: `WebhooksController#verify_signature` selects the GitHub App / webhook secret to verify against based on `repository_owner`, which is read from `payload.dig('repository', 'owner', 'login')` (falling back to `payload.dig('organization', 'login')`). [1](#0-0) [2](#0-1) 

But the handler that actually acts on the payload (e.g. `PushHandler`) resolves the target `Repository`/`Stack` using a *different* field of the same payload: `payload.dig('repository', 'full_name')`, via `Handler#repository_name` / `Handler#stacks`. [3](#0-2) [4](#0-3) 

Because `verify_signature`'s HMAC check only proves the payload was signed by *some* organization's configured `webhook_secret` (chosen by `repository.owner.login`), nothing ties that verified organization to the `repository.full_name` value the handler subsequently trusts to look up `Repository.from_github_repo_name`. `Repository.from_github_repo_name` and `#github_app` independently derive trust from `owner`, but the webhook path never cross-checks that the signing organization's login matches the owner segment of `full_name` used downstream. [5](#0-4) [6](#0-5) 

This is the "organization that authenticated versus the repository that is written" binding from the rules — analogous to `safeApprove()` being invoked against one binding (the previous allowance) while a second, differently-scoped call is trusted to have the same effect: here, the signature check authenticates one organization identity, while the object actually mutated (`Stack`/`Repository`) is chosen from an unguarded field of the same untrusted JSON body.

### Title
Webhook signature verifies signing organization but handlers act on an unverified `repository.full_name` field, allowing cross-repository writes - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the webhook secret / GitHub App to verify against using `repository.owner.login` (or `organization.login`) from the raw JSON body, and only checks the HMAC signature over the whole payload with that org's secret. Handlers, however, resolve which `Stack`/`Repository` to mutate using `repository.full_name` — a separate field inside the very same signed body — via `Handler#repository_name`/`Handler#stacks`. Nothing enforces that the `owner.login` used to select the signing secret matches the owner segment of `full_name` used to select the target repository.

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (or `organization.login`), fetches that organization's `GitHubApp` via `Shipit.github(organization: repository_owner)`, and validates `X-Hub-Signature` against that org's `webhook_secret`. [7](#0-6) 

If that succeeds, `WebhooksController#create` dispatches the parsed body unchanged to every registered handler for the event. [8](#0-7) 

Each `Handler` computes `repository_name` from `payload.dig('repository', 'full_name')` and looks up stacks with `Repository.from_github_repo_name(repository_name)&.stacks`. [3](#0-2) 

`PushHandler#process`, for example, uses those stacks to call `stack.sync_github(expected_head_sha: params.after)`, which queues `GithubSyncJob`, ultimately fetching and updating commits for that stack from the given ref. [4](#0-3) 

In a multi-tenant Shipit deployment — the engine explicitly supports configuring multiple organizations, each with its own `app_id`/`installation_id`/`webhook_secret` (as shown by the two-org fixture) — an entity that legitimately controls one organization's GitHub App/webhook configuration (e.g. is an org owner or has installed the app on org "OrgTwo", which the fixtures show can even have `webhook_secret: nil`) can sign (or, if unset, send unsigned) a payload whose `repository.owner.login`/`organization.login` is "OrgTwo" but whose `repository.full_name` names a repository belonging to a different, unrelated organization ("OrgOne") that is also tracked by the same Shipit instance. [9](#0-8)  `verify_webhook_signature` will pass (it validates against OrgTwo's secret, or trivially returns `true` if that org has no secret configured), yet the handler will act on the OrgOne repository named in `full_name`, because that field was never covered by the signature-organization binding.

### Impact Explanation
This breaks the equality "organization that authenticated == repository that is written." An attacker who only controls the webhook trust boundary of one (possibly low-privilege or secret-less) GitHub organization/App installation can forge events (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.) that are processed as if they originated from, and target, a completely different, unrelated repository's stack. Depending on which webhook `event`/handler is targeted, this can trigger unauthorized `GithubSyncJob` runs, alter commit/CI status records (`status_master`-style handlers create `Commit::Status` rows purely from `sha`/`state` in the body), or otherwise write state for a repository/stack the attacker has no legitimate relationship to — a cross-repository write that the rules classify as Critical impact.

### Likelihood Explanation
Any Shipit deployment configuring more than one GitHub organization (a documented, supported configuration, see `config/secrets_double_github_app.yml` fixture with `OrgOne`/`OrgTwo`) is exposed. The attacker only needs the ability to trigger a webhook delivery signed with (or, if unconfigured, unsigned for) one organization's secret — something an org owner/App installer of that one organization can already do — and to craft the `repository.full_name` field pointing at another tracked repository. No `ApiClient` token, session, or GitHub write access to the target repository is required, which keeps this within the "unprivileged attacker" scope defined by the rules.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after successfully verifying the signature for `repository_owner`, additionally assert that the `owner` segment of `repository.full_name` (and/or `organization.login`) used by downstream handlers is the same organization whose secret validated the signature, rejecting the request (e.g. `head(422)`) otherwise. Equivalently, `Handler#repository_name` could re-derive the repository strictly from the same `owner.login` field that was used for signature verification rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` (attacker-controlled GitHub App/webhook secret) and `orgB` (victim, tracked repository `orgB/secret-repo`), as supported by the engine's multi-org config format. [9](#0-8) 
2. Attacker, who administers orgA's GitHub App/webhook, crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/secret-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature` using orgA's known `webhook_secret` (or sends it unsigned if orgA has none configured) and POSTs to the Shipit webhooks endpoint.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches orgA's `GitHubApp`, and the signature check passes (or is skipped) because `owner.login` is `orgA`. [1](#0-0) 
5. `PushHandler` resolves `repository_name` from `full_name` = `"orgB/secret-repo"`, finds `orgB`'s tracked stacks, and triggers `stack.sync_github(expected_head_sha: ...)` on the victim organization's repository — despite the request never having been authenticated by orgB's credentials. [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
