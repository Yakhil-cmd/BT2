This confirms the vulnerability. I have enough to finalize.

### Title
Webhook organization used for signature verification is decoupled from the repository the payload actually writes to, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to validate the `X-Hub-Signature` against based solely on `payload.dig('repository','owner','login')` (falling back to `payload.dig('organization','login')`). However, every event handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, and by extension `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`) resolves the actual repository/stack to act on independently, from `payload.dig('repository','full_name')`. Nothing ties `repository.full_name` to `repository.owner.login` used for verification, so the field that authenticates the request is not the field the handlers act on — the same class of bug as the lending threshold check that used one value (`externalUnderlyingAvailableForWithdraw`) to bound an action that actually changes a different, related-but-independent value.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
This picks the `webhook_secret` for whatever organization name appears in `repository.owner.login`, and if that HMAC check passes, `create` dispatches the same raw JSON to every registered handler for the event [2](#0-1) .

Every handler, however, determines the concrete repository/stack to mutate from a *different* field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler#process` [4](#0-3)  and `StatusHandler#process` [5](#0-4)  (which matches purely on commit `sha`, not even scoped by repository) then perform writes (`stack.sync_github`, `commit.create_status_from_github!`) against whatever repository/commit the payload names, with no requirement that `repository.full_name`'s owner matches `repository.owner.login`.

`Shipit.github(organization: ...)` supports per-organization `webhook_secret`s specifically for the documented "Using Multiple Github Applications" setup [6](#0-5) , so it is expected and supported for a Shipit instance to serve several independent GitHub organizations, each with their own app credentials/secret, feeding into one shared webhook endpoint and shared handler pipeline.

Breaking this down as an equality that the code should, but does not, enforce:

`organization_authenticated (repository.owner.login)` == `organization_of_repository_written (repository.full_name.split('/').first)`

Before the attack: for a legitimately signed webhook these two are always equal because GitHub sets both fields from the same real repository. After the attack: an attacker who is an admin/owner of Organization A (and therefore knows Organization A's `webhook_secret`, which they configured when installing/creating the Shipit GitHub App for their own org) can send a POST to the shared `/webhooks` endpoint with:
```json
{
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "org-a" } },
  "ref": "refs/heads/master",
  "after": "<any-existing-sha-in-victim-repo>"
}
```
signed with `X-Hub-Signature` computed using Organization A's `webhook_secret`. `repository_owner` resolves to `"org-a"`, `verify_webhook_signature` succeeds (it's genuinely Org A's secret over this exact body), yet `PushHandler` resolves the stack via `repository.full_name = "victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: params.after)` on a stack the attacker has no relationship to.

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written," letting a party with legitimate control of one configured GitHub organization forge state-changing webhook events (`push` triggering `sync_github`, `status` writing commit statuses via `StatusHandler`, `check_suite` scheduling check-run refreshes) against stacks belonging to a completely different, unrelated organization/repository — i.e. unauthorized cross-repository writes, matching the Critical-impact category "cross-repository writes" defined in scope.

### Likelihood Explanation
Exploitability requires only that the Shipit instance is configured with more than one GitHub organization (a documented, supported configuration) and that the attacker controls the GitHub App/webhook secret of any one of them — a realistic scenario for shared/multi-tenant Shipit deployments where different teams manage their own org's GitHub App credentials but rely on the same Shipit deployment. No Shipit session, `ApiClient` token, or access to the victim repository is required.

### Recommendation
Do not select the verifying organization from an attacker-controlled field independent of the field handlers act on. After signature verification succeeds for organization `O`, require that every repository/organization value used by the dispatched handler (`repository.full_name`'s owner segment, or `organization.login`) equals `O`, rejecting the event (422) otherwise. Alternatively, attempt verification only against the webhook secret configured for the organization implied by `repository.full_name`, not `repository.owner.login`, and reject if `repository.owner.login` disagrees.

### Proof of Concept
1. Deploy Shipit configured with multi-org `github:` block containing `org-a` (secret known to attacker as its admin) and `victim-org` (holds a `victim-repo` with an existing stack).
2. Attacker crafts a `push` webhook JSON body:
```json
{"ref":"refs/heads/master","after":"<existing sha on victim-repo/master>","repository":{"full_name":"victim-org/victim-repo","owner":{"login":"org-a"}}}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-a webhook_secret, body)>` and POSTs to `/webhooks` (mounted engine webhook route) with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` → `"org-a"`, verifies successfully against `org-a`'s secret [7](#0-6) .
5. `PushHandler` looks up `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack [4](#0-3) , forcing an unauthorized sync/deploy trigger on a repository the attacker does not control.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
