### Title
Cross-organization status forgery via webhook signature scoped to sender org but `status` handler resolves commits globally by SHA - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The webhook signature check in `WebhooksController#verify_signature` binds the HMAC verification to the organization named in the payload's `repository.owner.login` (or `organization.login`) field [1](#0-0) , selecting the `Shipit::GithubApp` (and its `webhook_secret`) for that organization [2](#0-1) . However `Handlers::StatusHandler#process` never re-checks which repository/organization owns the payload — it looks up commits **globally by SHA** across the whole database and writes a status onto them: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . The `status` event's parameter schema doesn't even require a `repository` block [4](#0-3) .

### Finding Description
This is the equivalent of the `amount` binding bug: a field that gates a privileged action (`sha`/target commit) is disconnected from the field that is actually authenticated (`repository_owner`/organization). The binding that should hold is:

`organization whose secret signed the request == organization owning the commit acted upon`

In a Shipit instance configured for multiple GitHub organizations (an explicitly supported and documented configuration, see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`) [5](#0-4) , each organization has its own `webhook_secret`. An administrator/owner of "OrgOne" (who legitimately knows/controls OrgOne's GitHub App webhook secret, since they administer that org's GitHub App settings) can POST directly to the shared, public `/webhooks` endpoint with:
- `X-Github-Event: status`
- a JSON body whose `repository.owner.login` (or `organization.login`) is `"OrgOne"` (so `verify_signature` selects OrgOne's app/secret) [2](#0-1) 
- `sha` set to the SHA of a commit belonging to a completely unrelated stack/repository (e.g. `"OrgTwo/some-repo"`), plus arbitrary `state`, `description`, `context`, `target_url` fields
- `X-Hub-Signature` computed with OrgOne's own webhook secret over that raw body

`verify_signature` only checks that the HMAC matches the secret for the organization named in the payload; it never checks that the commit found by `Commit.where(sha: ...)` actually belongs to a repository under that same organization [6](#0-5) . Because `StatusHandler` performs a global commit lookup with no `repository_name`/stack scoping (unlike other handlers such as `PushHandler`/pull-request handlers which resolve via `Repository.from_github_repo_name(...)`), the forged status is applied to a commit owned by a different, unrelated organization/repository [7](#0-6) .

### Impact Explanation
Commit statuses are used by Shipit to gate merges and deploys (deployable/blocking status checks referenced in `app/models/shipit/commit.rb`, `app/models/shipit/deploy_spec.rb`, `app/models/shipit/commit_checks.rb`). An attacker who legitimately controls one tenant organization's GitHub App/webhook secret in a multi-org Shipit deployment can forge a `success` status on a commit belonging to a different organization's stack, potentially satisfying required-status-check gates and causing an unauthorized deploy/merge of a commit that never actually passed CI for that other organization — matching the "Critical: unauthorized deploy" impact bucket. At minimum it allows unauthenticated (relative to the target org) tampering with another org's commit/build state.

### Likelihood Explanation
Requires the Shipit instance to be configured for multiple GitHub organizations sharing one webhook endpoint (a documented, supported configuration) and requires the attacker to control one of those organizations' GitHub Apps (which is plausible in shared/multi-tenant Shipit deployments where one org's administrators are not trusted with another org's data). The `/webhooks` endpoint is public and unauthenticated aside from the per-organization signature check, so no Shipit session or `ApiClient` token is needed.

### Recommendation
In `StatusHandler` (and any other handler that doesn't already scope by repository), scope the `Commit` lookup to commits belonging to the repository/organization identified by the verified `repository_owner`/`repository.full_name` in the same payload — e.g., join through `stack.repository` and assert `repository.owner == verified_organization` — rather than trusting a global SHA lookup. Alternatively, thread the verified organization from `WebhooksController` into the handler and reject/ignore any payload whose `sha` resolves to a commit outside that organization.

### Proof of Concept
1. Configure Shipit with two GitHub Apps for `OrgOne` and `OrgTwo` (as in `test/dummy/config/secrets_double_github_app.yml`), each with a distinct `webhook_secret`.
2. As an administrator of `OrgOne`'s GitHub App, craft body:
```json
{
  "sha": "<sha of a commit tracked under an OrgTwo stack>",
  "state": "success",
  "description": "forged",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgOne" } }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgOne_webhook_secret, body)>`.
4. `POST /webhooks` with header `X-Github-Event: status` and the above body/signature.
5. `verify_signature` resolves `Shipit.github(organization: "OrgOne")` and validates successfully against OrgOne's secret [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and writes the forged `success` status onto the OrgTwo commit despite the request never being signed by OrgTwo's secret [3](#0-2) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
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
        -----BEGIN RSA PRIVATE KEY-----
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
