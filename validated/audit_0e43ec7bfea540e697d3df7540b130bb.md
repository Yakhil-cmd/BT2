### Title
Webhook organization used to select the HMAC secret is not bound to the repository the event payload acts on, enabling cross-repository status/push forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/webhook secret to use for signature verification based on `repository.owner.login` (or `organization.login`), while every event `Handler` resolves the `Stack`/`Repository` it operates on from an entirely different, independently-controlled field: `repository.full_name`. Nothing ties these two fields together, so on a Shipit instance configured for multiple GitHub organizations, an attacker who legitimately controls the webhook secret for their own organization can forge a signed payload whose `repository.owner.login` matches their own org (so the signature check passes) but whose `repository.full_name` names a repository belonging to a completely different, victim organization. This breaks the "organization authenticated" == "repository written" binding.

### Finding Description
Signature verification is performed before the event is dispatched to handlers: [1](#0-0) 

The organization used to look up the correct `github_app`/secret is taken from the raw, attacker-supplied JSON body itself: [2](#0-1) 

`verify_webhook_signature` simply HMACs the *entire* raw body with whichever org's secret was selected: [3](#0-2) 

Shipit explicitly supports configuring one GitHub App/secret per organization on a single instance: [4](#0-3) 

Once the signature is accepted, `create` dispatches the full parsed payload to all registered handlers for the event type without any further binding to the org that authenticated it: [5](#0-4) 

Every handler resolves the target `Stack`/`Repository` from `repository.full_name`, a field completely independent of `repository.owner.login`: [6](#0-5) 

Because an attacker who owns "OrgA" (a legitimately configured organization on the shared Shipit instance) knows OrgA's `webhook_secret`, they can:
1. Build a JSON payload with `repository.owner.login = "OrgA"` (so `Shipit.github(organization: "OrgA")` selects OrgA's secret) and `repository.full_name = "OrgB/victim-repo"`.
2. Sign the whole raw body with OrgA's `webhook_secret` — `verify_webhook_signature` passes because it only checks the HMAC against the selected org's secret over the raw bytes, not that the payload's internal fields are internally consistent.
3. The handler pipeline (e.g. `StatusHandler`, `PushHandler`) then acts on `repository.full_name = "OrgB/victim-repo"`, a repository the attacker has no legitimate write access to.

`StatusHandler#process` applies attacker-controlled commit statuses to any commit matching `params.sha` across the whole install, independent of which org's key signed the request: [7](#0-6) 

`PushHandler#process` similarly triggers a sync/deploy-relevant job (`sync_github`) for stacks resolved purely from `repository.full_name`: [8](#0-7) 

### Impact Explanation
Forged commit statuses feed directly into deployability and merge-queue gating decisions elsewhere in the engine (e.g. `until_commit.deployable?` consulted in `Stack#build_deploy`). An attacker who only controls one organization's webhook secret on a shared multi-org Shipit instance can inject fabricated "success" CI statuses for commits in a victim organization's repository they do not control, which can cause an otherwise-blocked commit to be treated as deployable/mergeable — i.e., contribute to an unauthorized deploy or merge, and can trigger sync jobs for stacks/repositories outside the attacker's authorization boundary. This crosses a repository-authorization boundary without any Shipit account, API-client token, or GitHub write access to the victim repository, satisfying the Critical "cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Requires only that the target instance host more than one GitHub organization (a supported, documented configuration — see `secrets_double_github_app.yml` and the multi-org example in `config/secrets.development.example.yml`) and that the attacker control (or be authorized to configure) one such organization's webhook. No privileged Shipit session, `ApiClient` token, or victim-repo access is needed; only knowledge of one's own org's `webhook_secret`, which is inherently accessible to whoever configures that org's GitHub App/webhook.

### Recommendation
Bind the verified organization to the payload's actual target repository before dispatching to handlers: after `verify_signature` succeeds, re-derive `repository_name`/`full_name` and assert its owner segment equals `repository_owner` (the same value used to select the secret), rejecting the webhook (422) on mismatch. Alternatively, resolve the `Repository`/`Stack` via the verified organization context rather than trusting an unrelated field inside the same unauthenticated-until-verified payload.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` (attacker-controlled, secret known to attacker) and `OrgB` (victim), as in `test/dummy/config/secrets_double_github_app.yml`.
2. Craft a `status` (or `push`) event JSON body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(body, OrgA_webhook_secret)>` and POST to `/github/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#repository_owner` returns `"OrgA"`, so `Shipit.github(organization: "OrgA")` is used and the signature verifies successfully.
5. `StatusHandler` looks up `Commit.where(sha: params.sha)` across the whole instance and applies the forged "success" status to the victim's commit in `OrgB/victim-repo`, even though the request was never signed with `OrgB`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
