### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while every event handler trusts the unrelated `repository.full_name` field, letting a signature valid for one GitHub organization forge events for a stack in another organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`) in the *unverified* JSON body. [1](#0-0) [2](#0-1)  Once the signature check passes, `create` dispatches to `Shipit::Webhooks::Handlers::Handler`, whose `stacks`/`repository_name` helpers key off a completely different field of the same untrusted payload: `payload.dig('repository', 'full_name')`. [3](#0-2)  Nothing ties `repository.owner.login` to `repository.full_name`, so the field whose organization is authenticated (`owner.login`) is not the field that is actually written to (`full_name`).

### Finding Description
Shipit explicitly supports multiple GitHub organizations, each with its own `webhook_secret`, configured under the `github:` key in `secrets.yml`. [4](#0-3)  `GitHubApp#verify_webhook_signature` compares the `X-Hub-Signature` against an HMAC computed with the secret of the single organization returned by `Shipit.github(organization: repository_owner)`. [5](#0-4) 

`repository_owner` is derived purely from the request body before the signature has been checked:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

After `verify_signature` succeeds, `create` hands the same raw `params` to every registered handler for the event (e.g. `PushHandler`, `StatusHandler`, `PullRequest::*Handler`, `CheckSuiteHandler`). [6](#0-5)  All of these handlers resolve the target `Repository`/`Stack` via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` - not `repository.owner.login`. [3](#0-2)  `PushHandler#process`, the pull-request handlers, and `StatusHandler#process` all key their side effects (triggering `sync_github`, creating/archiving review stacks, or attaching a commit status) on that same `full_name`/`sha` value without any owner cross-check. [7](#0-6) [8](#0-7) [9](#0-8) 

This is exactly the ParaSpace bug class translated to a signing/authorization mismatch: the value that is verified (`repository.owner.login`, used to pick the org's `webhook_secret`) is not the value that is acted upon (`repository.full_name`, used to find and mutate the target `Stack`/`Repository`/`Commit`). An attacker who legitimately controls (or has obtained) the `webhook_secret` for one configured GitHub organization ("Org A") - e.g. because they administer their own GitHub App/organization that is also configured in the same Shipit instance for legitimate reasons - can craft a payload where:
- `repository.owner.login` = `"org-a"` (matches the secret they hold, so `verify_webhook_signature` passes)
- `repository.full_name` = `"org-b/victim-repo"` (an unrelated stack hosted under a different, victim organization also tracked by this Shipit instance)

Because `verify_signature` only checks the HMAC against Org A's secret and never checks that `full_name`'s owner equals `repository.owner.login`, the forged event is accepted and processed as if it legitimately originated from Org B.

### Impact Explanation
Concretely reachable, high-impact consequences without any Shipit session, `ApiClient` token, or GitHub write access to the victim repository:
- `StatusHandler#process` calls `commit.create_status_from_github!(params)` for any `Commit` matching the forged `sha`, letting the attacker inject a fabricated `success` CI status context for a victim commit they don't control. [8](#0-7)  Since deploy safety gates (`ci.require`, `ci.blocking`) are driven by these stored statuses, this can enable an **unauthorized deploy** of a commit that never actually passed CI in the victim's real organization.
- `PushHandler#process` can trigger `stack.sync_github(expected_head_sha:)` for a victim stack using an attacker-chosen `after` SHA. [7](#0-6) 
- `PullRequest::OpenedHandler`/`LabelCapturingHandler` can create or archive review stacks belonging to the victim repository based on a forged `full_name`. [10](#0-9) 

This satisfies the required Critical/High impact bar ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitability depends entirely on the attacker holding a valid `webhook_secret` for *any one* of the organizations configured in the same Shipit deployment's multi-org `github:` config, which the docs and `secrets.development.shopify.yml` show is an explicitly supported topology (multiple orgs sharing one Shipit instance). [4](#0-3)  No repository write access, Shipit session, or `ApiClient` token to the victim org is needed - only the ability to send an HTTP POST with a validly-signed (for org A) but cross-referencing payload. In a single-organization Shipit deployment this specific analog does not apply since there is only one secret and one org, so likelihood is contingent on the multi-org configuration being used.

### Recommendation
In `WebhooksController#verify_signature`, after selecting the `GitHubApp` config, verify that the field used to select the secret (`repository.owner.login` / `organization.login`) matches the owner encoded in `repository.full_name` before dispatching to handlers, e.g.:
```ruby
def verify_signature
  ...
  return head(422) unless repository_owner_matches_full_name?
end

def repository_owner_matches_full_name?
  full_name = params.dig('repository', 'full_name')
  return true if full_name.blank?
  full_name.split('/').first&.casecmp?(repository_owner)
end
```
Alternatively, always derive the org used for secret lookup from the same `full_name` field the handlers use, so a single unambiguous field is both authenticated and acted upon.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`, `org-a` (secret `S_A`) and `org-b` (secret `S_B`), with a real stack tracking `org-b/victim-repo`.
2. Attacker (who has `S_A`, e.g. as owner of a low-privilege GitHub App installed on `org-a`) builds a `status` webhook payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_A, body)` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature using `S_A`. [1](#0-0) 
5. `create` dispatches to `StatusHandler`, which looks up `Commit.where(sha: params.sha)` - matching the victim commit belonging to `org-b/victim-repo` - and calls `create_status_from_github!`, injecting a forged passing CI status for a commit the attacker never had permission to send events for. [8](#0-7)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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
