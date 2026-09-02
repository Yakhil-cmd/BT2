### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but stack lookup/mutation uses the independent `repository.full_name` field, letting a webhook signed by one onboarded organization act on any other tracked repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by choosing which GitHub App/webhook secret to check against based on `repository.owner.login` (falling back to `organization.login`) parsed from the raw request body. Once the HMAC check passes, the entire raw JSON body is handed unmodified to the registered event handlers, which locate the `Stack`/`Repository` to mutate using a *different* field of the same attacker-supplied payload: `repository.full_name`. These two fields are never cross-checked against each other, so the "organization whose secret authenticated the request" and "the repository that gets written to" are not the same binding.

### Finding Description
`verify_signature` picks the verification secret using only the owner login: [1](#0-0)  and resolves that owner via: [2](#0-1) 

After the signature check passes, `create` dispatches the *raw* parsed JSON to handlers without re-validating any field: [3](#0-2) 

Every handler resolves the target `Stack`/`Repository` from a completely separate field, `repository.full_name`: [4](#0-3) 

For example the push handler uses that lookup to enqueue a sync against whatever stacks match: [5](#0-4) 

`Shipit` explicitly supports onboarding multiple, independently-configured GitHub organizations, each with its own `webhook_secret`, as documented in the setup guide: [6](#0-5) 

Because the webhook secret is scoped to an *organization* (selected via `repository.owner.login`) while the *repository actually mutated* is selected via the unrelated `repository.full_name` field, nothing in the code enforces that these two values point to the same GitHub repository. Both fields live in the same attacker-controlled JSON body that is signed by the attacker's own organization's secret, so an entity that legitimately owns one onboarded organization (and therefore possesses/can produce a valid signature for that organization's webhook secret) can freely set `repository.full_name` to `"victim-org/victim-repo"` while keeping `repository.owner.login` equal to their own organization, satisfying `verify_signature` while acting on a stack that belongs to a completely different, unrelated GitHub organization tracked by the same Shipit instance.

This is the exact binding-break pattern described by the report: it is analogous to `COINBASE` returning a hardcoded/empty value disconnected from the actually-verified block proposer — here, the "organization authenticated" (`repository.owner.login`, checked against a specific org's `webhook_secret`) is not the same entity as "the repository that is written" (`repository.full_name`, used by every handler to find the `Stack`).

### Impact Explanation
This crosses a repository-authorization boundary explicitly called out as in-scope ("an organization that authenticated versus the repository that is written"). Concretely, using the `push` handler, an attacker who legitimately controls one onboarded GitHub organization/App can force `GithubSyncJob` to run against an unrelated victim stack, causing it to fetch and record whatever `expected_head_sha` the attacker names, and to enqueue `CacheDeploySpecJob`/mark the stack accessible — effectively record injection into another team's deploy history and cache invalidation without any credentials for the victim repository. Other handlers (e.g. `pull_request` `LabeledHandler`/`ReopenedHandler`) can similarly archive/unarchive review stacks belonging to a repository the attacker does not own, by supplying a `repository.full_name` that doesn't match the signing org. This meets the High bar of "escalation into `Shipit.github_teams` authorization" / repository-state mutation across an authentication boundary, since it lets an actor authenticated for org A alter tracked state for org B's stacks.

### Likelihood Explanation
Any party that operates a legitimately configured, non-privileged GitHub App/organization on a multi-org Shipit instance (a documented, supported configuration) can compute a valid signature for their own webhook secret and simply set an arbitrary `repository.full_name` in the JSON body — no repository write access, no session, and no API token is required, only the ability to send an HTTP POST to `/webhooks` with a body signed with their own known secret.

### Recommendation
After `verify_signature` succeeds, cross-check that the `repository.owner.login`/`organization.login` used to select the verifying secret matches the owner segment of `repository.full_name` (and reject the webhook if they diverge) before dispatching to any handler, or resolve the target `Repository`/`Stack` using the same organization identity that was cryptographically verified rather than trusting an independent field from the unauthenticated part of the payload.

### Proof of Concept
1. Onboard two organizations in `config/secrets.yml` per the documented multi-org setup (`attacker-org` with its own `webhook_secret`, and `victim-org` tracked by Shipit with a stack for `victim-org/victim-repo`). [6](#0-5) 
2. Craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Compute `X-Hub-Signature` using `attacker-org`'s own `webhook_secret` (owned/known by the attacker) and set `X-Github-Event: push`.
4. POST to `/webhooks`. `verify_signature` resolves the org via `repository_owner` → `"attacker-org"`, verifies successfully against the attacker's own secret. [1](#0-0) 
5. `PushHandler#process` looks up stacks via `repository.full_name` = `"victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: params.after)` for the victim's stack, even though the signature only proved the attacker controls `attacker-org`. [5](#0-4) [4](#0-3)

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
