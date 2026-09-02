### Title
Cross-organization CI status forgery via webhook leads to unauthorized deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an incoming webhook against the GitHub App/webhook secret belonging to the *organization* named in the payload's `repository.owner.login` field [1](#0-0) , but the event handler that actually mutates state — `StatusHandler` — never checks that the commit it updates belongs to that same organization/repository. It looks up commits globally by SHA: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . This breaks the binding "organization authenticated == repository/commit written."

### Finding Description
The webhook signature check selects which secret to verify against using only the organization owning the *claimed* repository:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

In a multi-organization Shipit deployment (explicitly a supported configuration, see `config/secrets.development.shopify.yml`, where each organization has its own `webhook_secret`), each organization has an independently-known `webhook_secret` tied to its own GitHub App. An administrator/maintainer of *any one* of these organizations legitimately knows (or can obtain, since they administer that org's GitHub App settings) their own organization's `webhook_secret`.

Once the signature is verified using OrgB's secret, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire, attacker-controlled* payload to the handler [4](#0-3) . The `status` event is routed to `StatusHandler`, whose `process` method does not scope by repository or organization at all — it looks up `Commit` records purely by `sha`, a value that is global across the whole Shipit installation:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Since the attacker fully controls the raw JSON body before signing it with their own known secret, they can set `repository.owner.login` to their own organization (to pass `verify_signature`) while independently setting `sha`, `state`, `context`, and `target_url` to target a commit that actually belongs to a *different* organization's stack. Because `StatusHandler` performs no cross-check against `repository.owner.login`/`repository.full_name`, the forged status is written to that unrelated commit.

### Impact Explanation
A forged, attacker-controlled CI status (e.g., `state: success`, matching a `required_statuses` context) on an arbitrary commit belonging to another organization's stack can satisfy `Commit#deployable?` checks used for continuous deployment / manual deploy gating. This enables an unauthorized deploy of a commit that never actually passed CI/review in the target organization's stack — one of the explicitly listed Critical impacts ("an unauthorized deploy, rollback or merge"). It is also a cross-repository/cross-organization write, since state belonging to Organization A's commit is modified by an actor who only authenticated as Organization B.

### Likelihood Explanation
This requires the attacker to control a legitimate `webhook_secret` for *some* organization configured on the shared Shipit instance (a realistic condition in any multi-tenant setup where multiple orgs' GitHub Apps point at the same Shipit deployment, since each org's admins configure their own app and its secret). It also requires knowledge of a target commit SHA, which is generally public/discoverable (visible on GitHub, PR pages, CI logs, etc.). No repository write access or Shipit session/API token is needed — only the ability to send a correctly-signed HTTP request to the public `/webhooks` endpoint.

### Recommendation
`StatusHandler` (and any other handler that mutates records looked up independent of `repository`) must scope its lookups through `stacks`/`Repository.from_github_repo_name(repository_name)` (as `Handler#stacks` already does) rather than querying `Commit` globally by `sha`. Concretely, restrict the query to commits belonging to the repository identified in `payload['repository']['full_name']`, and additionally verify that this `repository.full_name`'s owner matches `repository_owner`, the value used to select the webhook secret in `WebhooksController#verify_signature`.

### Proof of Concept
1. Attacker administers "OrgB" GitHub App on the shared Shipit instance and knows OrgB's `webhook_secret` (they configured it during app creation, per `docs/setup.md`).
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<sha of a commit belonging to OrgA/victim-repo, required-status commit>",
  "state": "success",
  "context": "<required CI context configured on OrgA's stack>",
  "target_url": "https://ci.example.com/fake",
  "repository": { "owner": { "login": "OrgB" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgB_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = "OrgB", fetches OrgB's `Shipit.github`, and verifies successfully because the signature was computed correctly with OrgB's secret [5](#0-4) .
5. `StatusHandler#process` then finds the commit purely by `sha` (belonging to OrgA/victim-repo) and calls `create_status_from_github!(params)`, writing a fraudulent "success" status onto it, with no check that OrgA and OrgB are the same organization [2](#0-1) .
6. If OrgA's stack has continuous deployment enabled and gates on that CI context, this fraudulent status can make the commit `deployable?`, triggering an unauthorized deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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
