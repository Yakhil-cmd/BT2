## Finding

### Title
Webhook status events write to any repository's commits regardless of which organization's secret authenticated the request - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate a webhook by looking at the *organization* named in the payload, then dispatches the event to a handler that mutates state identified only by a `sha` string with no check that the sha belongs to a repository owned by that organization. For the `status` event this means a forged webhook signed with **any** configured organization's `webhook_secret` can flip the CI/deploy status of a commit belonging to a **completely different** organization/repository hosted on the same Shipit instance.

### Finding Description
Signature verification is org-scoped: `WebhooksController#verify_signature` resolves `repository_owner` from the payload and fetches that organization's `GitHubApp` to check the HMAC: [1](#0-0) [2](#0-1) 

Shipit explicitly supports multiple independent GitHub Apps/organizations sharing one instance, each with its own `webhook_secret`: [3](#0-2) 

Once the signature is accepted for organization X, the raw payload is handed to the matching handler: [4](#0-3) 

Most handlers scope their side effects to a specific repository via `Handler#repository_name`/`#stacks`, which reads `repository.full_name` from the payload: [5](#0-4) 

But `StatusHandler#process` never calls `stacks`/`repository_name` at all — it looks up commits globally by `sha` across the entire `Commit` table and writes a status to every match: [6](#0-5) 

`sha` is a 40-character git hash that is public information (visible in GitHub UI, PRs, git history) and is not scoped to the organization whose secret authenticated the request. There is no equality check enforced anywhere between "organization whose `webhook_secret` validated the HMAC" and "repository/organization the written `Commit` row belongs to."

Binding that should hold but doesn't:
`organization authenticated by verify_signature == organization owning the Commit mutated by the handler`

Before the attacker's request: commit `sha` in victim org Y's stack has whatever status GitHub CI last reported.
After the attacker's forged `status` webhook (signed with org X's `webhook_secret`, `sha` set to a commit that happens to exist in org Y's tracked repository, `state: success`, `context` matching the release-status context Y's stack expects): the commit's status row is created/overwritten as passing, even though the request was never signed by anything related to org Y.

### Impact Explanation
If the targeted stack in org Y has a configured `release_status.context` and continuous deployment (deploy-on-green) enabled, forging a passing status for a real commit sha can push that commit into "deployable"/"green" state and trigger an automatic deploy the attacker never had access rights to initiate — an unauthorized deploy driven entirely by a credential (webhook secret) belonging to an unrelated organization. This satisfies the Critical impact bar ("cross-repository writes" / "an unauthorized deploy") because the attacker never needed any credential, session, or repository permission tied to the victim organization or repository — only the ability to have a legitimately configured (but unrelated) org's webhook secret trigger a request to `/webhooks`, plus knowledge of a target commit sha (obtainable from GitHub's public commit history/PRs).

### Likelihood Explanation
Requires: (1) the Shipit instance is configured with more than one GitHub App/organization (an explicitly documented and supported configuration, see `config/secrets.development.shopify.yml`), (2) the attacker controls/knows the `webhook_secret` for at least one configured organization (e.g., because they administer their own org that is also hooked into the same Shipit instance), and (3) knowledge of a target commit sha in the victim stack (public). No repository write access, no `ApiClient` token, and no privileged Shipit account are needed — exactly the unprivileged-attacker, credential-scope-crossing scenario in the report's bug class (a value acted upon that isn't actually bound/verified against the authenticated principal).

### Recommendation
Scope `StatusHandler` (and any other handler that does not already call `stacks`/`repository_name`) to the repository named in the payload, and additionally verify that the `repository.owner.login` (or `organization.login`) used for HMAC secret selection matches the owner of the repository the handler is about to mutate, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner })`. More generally, add a check in `WebhooksController` (or `Handler`) enforcing that the organization whose secret validated the signature equals the organization implied by every repository-identifying field consumed by the handler, closing the gap between "who authenticated" and "what gets written."

### Proof of Concept
1. Shipit is configured with two orgs, `orgX` (attacker-controlled/known secret `SECRET_X`) and `orgY` (victim, unrelated secret).
2. Victim stack tracks `orgY/victim-repo`; obtain a real commit `sha` from that repo's public history (e.g. from a PR/branch), and note the stack's `release_status.context`.
3. Craft a `status` event payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "<victim stack's release_status context>",
  "branches": [{"name": "<victim branch>"}],
  "repository": {"owner": {"login": "orgX"}, "full_name": "orgX/some-repo"}
}
```
4. Sign the raw JSON with `HMAC-SHA1(SECRET_X, payload)` and send it to `/webhooks` with `X-Github-Event: status` and `X-Hub-Signature: sha1=<hmac>`.
5. `verify_signature` resolves `repository_owner` to `"orgX"`, fetches `orgX`'s `GitHubApp`, and the signature validates using `SECRET_X` — attacker fully controls this secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (regardless of the `orgX` value used for signing), and calls `create_status_from_github!`, marking it green in `orgY`'s stack — with `orgY`'s continuous deployment potentially triggering a real deploy.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
