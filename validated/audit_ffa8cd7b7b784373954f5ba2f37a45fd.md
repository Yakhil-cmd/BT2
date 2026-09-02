### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while push/status/pull_request handlers act on the independently-controlled `repository.full_name` field, allowing a valid signature from one GitHub organization's app to authorize writes against any other organization's Stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1) 

Once the signature is accepted, the same raw JSON payload is dispatched to handlers (`PushHandler`, `StatusHandler`, PR handlers, etc.) which independently resolve the target `Repository`/`Stack` using a *different* field of the same payload: `payload.dig('repository', 'full_name')` in `Shipit::Webhooks::Handlers::Handler#repository_name`. [3](#0-2) [4](#0-3) 

Nothing enforces that `repository.owner.login` (used to pick the verifying secret/organization) equals the owner segment embedded in `repository.full_name` (used to pick the acted-upon `Repository`). Because Shipit supports multiple independently-configured GitHub Apps/organizations, each with its own `webhook_secret`, and the webhook endpoint is a raw unauthenticated HTTP POST (not something only reachable via GitHub's own delivery infrastructure), a party who legitimately owns/administers *any one* configured organization's GitHub App knows that organization's `webhook_secret` and can craft an arbitrary raw POST body/signature pair.

### Finding Description
The verified binding should be: `organization whose secret signed the request == organization owning the repository being written to`. Instead the code checks: `organization whose secret signed the request == repository.owner.login (payload field A)`, then separately performs writes based on `repository.full_name (payload field B)`, with no cross-check that A and B refer to the same organization/repository.

- `verify_signature` builds `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(header, raw_post)` — this only proves the requester knows the webhook secret configured for whichever organization name is embedded in `repository.owner.login`/`organization.login`. [5](#0-4) 
- `create` then hands the *entire* parsed payload to `Shipit::Webhooks.for_event(event)` handlers unmodified. [4](#0-3) 
- `PushHandler#process` resolves the target stacks via `stacks` → `Handler#stacks` → `Repository.from_github_repo_name(repository_name)`, where `repository_name` reads `payload.dig('repository', 'full_name')`, a field completely separate from the one used for signature-org selection. [6](#0-5) [3](#0-2) 
- `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the target branch — an attacker-chosen `after` SHA sourced straight from the forged payload. [6](#0-5) 
- `StatusHandler#process` similarly writes a `Status` for any `Commit` matching an attacker-supplied `sha`, independent of the org used for signature verification. [7](#0-6) 

Concretely: an attacker who administers their own GitHub organization/App registered in Shipit's multi-org config (as documented for "Using Multiple Github Applications") [8](#0-7) 
knows that organization's `webhook_secret` [9](#0-8) 
and can POST directly to the webhook endpoint (it is not gated behind any session/token — see `skip_before_action :verify_authenticity_token`) [10](#0-9) 
with a body where `repository.owner.login = "attacker-org"` (so `verify_signature` picks the attacker's own known secret and passes) but `repository.full_name = "victim-org/victim-repo"`, `ref`, and `after` pointing at a real, already-registered victim `Stack`.

### Impact Explanation
This breaks the intended trust boundary between organizations: possession of one organization's webhook secret should only authorize writes to that organization's repositories/stacks, not any other tenant's. Since the handler's target resolution is decoupled from the signature-selection field, an attacker can force `GithubSyncJob`-style syncs (`stack.sync_github`) and status writes on stacks belonging to organizations they have no legitimate relationship with. If continuous delivery is enabled on the victim stack, an attacker-triggered sync to an attacker-chosen `expected_head_sha` can drive automatic deploy behavior on a stack outside their control — a cross-repository/cross-organization write and potential unauthorized deploy trigger, which the analog rules explicitly call out ("an organization that authenticated versus the repository that is written").

### Likelihood Explanation
Exploitation requires the attacker to control at least one organization/GitHub App that is configured in the target Shipit deployment's `config/secrets.yml` (multi-org setups are explicitly documented and supported), and requires the victim repository to already be a registered `Repository`/`Stack` in that same Shipit instance. This is a realistic scenario for any Shipit instance shared across multiple orgs/teams with differing trust levels, since the webhook endpoint itself performs no per-organization repository allow-listing beyond the mismatched field described above.

### Recommendation
After signature verification, re-derive the organization from the same trusted field used to select the verifying secret, and require that `repository.full_name`'s owner segment (or `repository.owner.login`) match the organization that successfully verified the signature before dispatching to handlers. Alternatively, bind `Repository.from_github_repo_name` lookups to also filter on the verified organization, rejecting payloads where the resolved repository's stored owner does not match the organization whose secret verified the request.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App/`webhook_secret` per the documented multi-org config. [8](#0-7) 
2. Attacker, who administers `attacker-org`'s GitHub App, knows `attacker-org`'s `webhook_secret`.
3. Attacker crafts a raw JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s known `webhook_secret` over this exact body, and sends `POST /github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` computes `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and successfully verifies the attacker-computed signature. [5](#0-4) 
6. `create` dispatches the full payload to `PushHandler`, which resolves `repository_name` from `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`, finds the real victim `Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — a write triggered on a stack the attacker does not own, authorized only by a signature scoped to a different organization. [3](#0-2) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-8)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** docs/setup.md (L181-209)
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
