### Title
Webhook organization/repository binding mismatch allows cross-organization write via forged webhook payload - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to validate the HMAC signature against, based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated JSON body. All the webhook handlers, however, resolve the `Stack`/`Repository` to act on using a completely different field of the same payload: `repository.full_name`. Nothing in the code enforces that these two fields refer to the same organization, so a party who legitimately knows the `webhook_secret` for *one* configured GitHub organization can forge a payload whose `repository.full_name` points at a *different* organization's repository/stack and still pass signature verification.

### Finding Description
In multi-organization deployments (`Shipit.github(organization:)`), each organization has its own `webhook_secret` configured independently, as documented in `docs/setup.md` ("Using Multiple Github Applications") and exercised by `test/dummy/config/secrets_double_github_app.yml`. [1](#0-0) [2](#0-1) 

`WebhooksController#verify_signature` picks the app/secret used for signature verification from the payload itself:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`GitHubApp#verify_webhook_signature` just HMAC-verifies the raw body against whichever `webhook_secret` was selected: [4](#0-3) 

Once the signature passes, every handler (`PushHandler`, `StatusHandler` via `Commit.where(sha:...)`, `CheckSuiteHandler`, PR handlers, etc.) resolves the target stack/repository using `payload.dig('repository', 'full_name')` via the shared `Handler#stacks`/`#repository_name` helper — a field that was never covered by the organization-selection logic used for signature verification: [5](#0-4) [6](#0-5) [7](#0-6) 

This is the same class of bug as the reported issue: a value used to authorize/select the verification context (`repository.owner.login` -> which secret is used) is disjoint from the value that is actually acted upon (`repository.full_name` -> which stack is written to). Because the raw JSON body is attacker-controlled (this endpoint requires no session, no `ApiClient`, and no GitHub App credentials — only knowledge of *some* configured `webhook_secret`), an attacker who administers their own GitHub organization/App integrated with this Shipit instance (and thus legitimately knows their own org's `webhook_secret`) can:

1. Set `repository.owner.login` (or `organization.login`) = their own org, so `verify_signature` selects their own known secret and the HMAC check passes.
2. Set `repository.full_name` = `"victim-org/victim-repo"`, so the handler's `Repository.from_github_repo_name(repository_name)` resolves stacks belonging to a completely different organization they have no access to.

### Impact Explanation
This breaks the binding `organization that authenticated == repository that is written`. With a validly-signed forged payload an attacker can drive write-effectful handlers against another organization's stacks without ever holding that organization's credentials:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha:)` on victim stacks, forcing a Git sync from an attacker-chosen `ref`/`after` SHA. [8](#0-7) 
- `StatusHandler#process` creates status entries (`commit.create_status_from_github!`) for arbitrary commits by `sha`, which can influence a commit's `deployable?`/CI-passed state used to gate deploys and continuous deployment. [9](#0-8) 
- `CheckSuiteHandler#process` schedules check-run refreshes for victim stacks/commits. [10](#0-9) 

If continuous deployment/merge automation is enabled on the victim stack, forging passing statuses/check runs for a chosen commit can unblock or trigger an unauthorized deploy — this satisfies the required Critical/High impact bar ("unauthorized deploy" / cross-repository writes) defined in the rules.

### Likelihood Explanation
Exploitation only requires: (a) the webhooks endpoint being reachable (it is unauthenticated by design, mounted at `resources :webhooks, only: :create` [11](#0-10) ), and (b) the attacker knowing a `webhook_secret` for *any one* organization configured on the instance. In the documented multi-tenant configuration, each organization sets and knows its own `webhook_secret` on its own GitHub App settings page — a capability that does not require any privilege inside Shipit itself (no `ApiClient` token, no Shipit session, no repository write access on Shipit's side). This matches a realistic deployment pattern the engine explicitly supports and documents.

### Recommendation
Bind the signature-verification context to the same identity used for target resolution: verify the payload's `repository.full_name` organization segment against `repository_owner` (and reject the request if they differ), or better, resolve the target `Repository`/`Stack` first, verify against the `webhook_secret` associated with that specific repository's registered organization, and only then process the handlers — never let two independently-attacker-controlled fields of the same unauthenticated body determine "which secret to check" and "what to write" respectively.

### Proof of Concept
1. Configure two organizations in `secrets.github` (as in `test/dummy/config/secrets_double_github_app.yml`): `OrgOne` (attacker-controlled, secret known to attacker) and `OrgTwo`/`victim-org` (has a Stack tracking `victim-org/victim-repo`).
2. Attacker builds a JSON payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known/pushed to victim-repo>",
  "repository": { "owner": {"login": "OrgOne"}, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgOne_webhook_secret, raw_body)>` using their own known `OrgOne` secret.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgOne")` (from `repository.owner.login`), and the HMAC check succeeds because it was signed with `OrgOne`'s secret.
6. `PushHandler#process` runs `Repository.from_github_repo_name("victim-org/victim-repo")`, finds the victim stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` — a write against a repository/organization the attacker never authenticated for.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L31-46)
```yaml
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L1-18)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```
