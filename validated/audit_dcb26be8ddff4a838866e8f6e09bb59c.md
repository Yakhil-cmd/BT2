### Title
Webhook signature is verified against the organization derived from `repository.owner.login`/`organization.login`, but every event handler acts on the unrelated `repository.full_name` field, letting anyone who controls a GitHub App for one org registered in this Shipit instance forge events against any other org's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret used to validate `X-Hub-Signature` by reading `repository_owner`, computed from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`). Every `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the repository/stack to act on from a completely different field of the same JSON body: `payload.dig('repository','full_name')` (or, for `PushHandler`, whichever stacks match `branch` across `Repository.from_github_repo_name(repository_name)`). Nothing ties `repository.owner.login`/`organization.login` to `repository.full_name` inside the same payload.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` comes from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .

This only proves the raw body was HMAC-signed with the secret configured for *that org's* GitHub App entry (Shipit supports multiple independent org configs, each with its own `webhook_secret` known to whoever set up that org's GitHub App, as shown in [3](#0-2)  and the setup instructions that explicitly tell an org admin to "fill it with some randomly generated string ... you'll need it later" [4](#0-3) ).

Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the raw parsed JSON [5](#0-4) . Every handler's base class resolves target stacks via `repository_name = payload.dig('repository', 'full_name')` [6](#0-5) , completely independent of the `repository.owner.login`/`organization.login` value used for signature selection. `PushHandler` uses this to trigger `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack [7](#0-6) , and the pull-request handlers use `params.repository.full_name` to locate `Shipit::Repository.from_github_repo_name(...)` and archive or provision review stacks [8](#0-7) [9](#0-8) .

This breaks a binding the system implicitly relies on: `organization authenticated by X-Hub-Signature == organization that owns the repository being acted upon`. In a multi-tenant Shipit deployment (multiple orgs configured under `Shipit.github`, as the sample secrets file demonstrates), any party who legitimately administers a GitHub App for **their own** small/throwaway organization (and therefore knows that org's `webhook_secret`) can POST directly to the shared `/webhooks` endpoint with a payload whose `repository.owner.login`/`organization.login` names their own org (so the signature check passes using a secret they know) while `repository.full_name` names an arbitrary victim org/repo that has a stack registered in the same Shipit instance. The handler then acts on the victim's stack because it never re-derives or cross-checks ownership from the field that was actually authenticated.

### Impact Explanation
This crosses the "organization that authenticated vs. repository that is written" trust boundary called out as in-scope. Concretely, an attacker who controls only their own org's GitHub App can:
- Forge `push` events causing `GithubSyncJob`/`stack.sync_github` to run against a victim's stack with an attacker-chosen `expected_head_sha`, injecting/altering commit and status state tracked for that stack.
- Forge `pull_request` events (`opened`/`closed`/etc.) to create, archive, or otherwise manipulate review stacks belonging to a victim repository the attacker has no access to.
- Depending on which handlers are registered (`membership`, `commit_status`, etc.), potentially influence merge-queue/CI status bookkeeping used elsewhere to gate real merges/deploys for the victim stack, since Shipit's merge/deploy logic trusts locally-recorded commit/status state that these handlers populate.

This is a cross-repository/cross-organization write achieved without any credential belonging to the victim org, matching the "cross-repository writes" Critical-impact category, though it does require the attacker to be a legitimate administrator of some other org onboarded to the same shared Shipit instance (a real precondition in Shipit's documented multi-org deployment model).

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with more than one organization's GitHub App/webhook secret (an explicitly supported and documented configuration, see `config/secrets.development.shopify.yml`), and (2) the attacker controls/administers at least one such onboarded organization (or otherwise knows its `webhook_secret`, e.g. a departed admin or a compromised low-trust org). No `ApiClient` token, session, or GitHub write access to the victim repository is needed. Likelihood is moderate — it depends on multi-org configuration being in use, but the code path itself has no additional barrier once that precondition holds.

### Recommendation
Cross-validate the two fields before dispatching to handlers: after computing `repository_owner` for signature selection, require that `params.dig('repository','full_name')&.split('/')&.first` (or `organization.login` for org-scoped events) matches `repository_owner` exactly, and reject (422) the webhook otherwise. Alternatively, resolve the target `Repository`/`Stack` first from `repository.full_name`, derive its configured GitHub App/organization from that resolved repository, and use that (not attacker-controlled payload fields) to select the webhook secret for signature verification, ensuring the same organization identity is used for both authentication and the write target.

### Proof of Concept
1. Attacker registers/administers a small GitHub App on their own org `attacker-org`, choosing `webhook_secret = "s3cr3t"`, and gets it added to the shared Shipit instance's `Shipit.github` config (a legitimate, supported multi-org setup as in `config/secrets.development.shopify.yml`).
2. Attacker crafts a payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1("s3cr3t", body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully because it was computed with that org's known secret [10](#0-9) .
5. `PushHandler#process` then resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` for the victim's stack [7](#0-6) [6](#0-5) , even though the victim org never issued this webhook and its secret was never involved.

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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
