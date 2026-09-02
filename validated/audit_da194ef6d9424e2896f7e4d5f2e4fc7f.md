### Title
Webhook signature verification is keyed on an attacker-controlled organization field that is decoupled from the repository field actually acted on, allowing cross-repository webhook forgery when any configured GitHub org lacks (or leaks) a `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to verify the HMAC signature against using `repository_owner`, a value read directly out of the untrusted JSON payload. The handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`) instead resolve the target `Repository`/`Stack` from a *different* payload field, `repository.full_name`. These two fields are never cross-checked against each other, so the "organization that authenticated" and the "repository that is written" are not bound together.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and uses it to pick the GitHub App config:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [2](#0-1) 

Signature verification itself is a no-op when that organization's `webhook_secret` is blank:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 
and the multi-organization config format documented in the setup guide explicitly allows per-organization `webhook_secret` values to be `nil`: [4](#0-3) 

Once `verify_signature` passes, `create` dispatches to handlers using the raw, already-verified body:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  ...
``` [5](#0-4) 

But the base `Handler` resolves the affected repository/stack from a sibling field that was never used in the org-selection/signature check:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

Concretely, for the `push` event, `PushHandler#process` triggers `stack.sync_github` for every non-archived stack on the matching branch of the resolved repository: [7](#0-6) 
and `StatusHandler#process` writes a fabricated CI/commit status onto any commit matching the attacker-chosen `sha` across the whole installation (not scoped to the resolved repository at all): [8](#0-7) 

**Root cause / broken binding:** `organization_used_to_verify_signature == payload.dig('repository','owner','login')` while `repository_actually_written == payload.dig('repository','full_name')`. Nothing forces `full_name`'s owner segment to equal `repository.owner.login`/`organization.login`. In a single-app deployment this is latent (there's only one org/secret, and if it's set the whole raw body is HMAC'd so tampering invalidates the signature). It becomes exploitable specifically in the documented multi-organization configuration (`docs/setup.md`, `config/secrets.development.example.yml`) where each org has an independently configured, possibly-blank `webhook_secret`: an unauthenticated attacker can send a POST to `/webhooks` with `repository.owner.login`/`organization.login` set to any org that has no `webhook_secret` configured (or whose secret has leaked) — bypassing `verify_webhook_signature` — while setting `repository.full_name` to `victim-org/victim-repo`, a completely different, protected stack tracked by Shipit. The handler layer only trusts `full_name` and performs no re-check that it belongs to the org that was verified.

### Impact Explanation
This breaks the trust boundary between "the organization whose webhook secret authorized this request" and "the repository whose state gets mutated," matching the External Report's bug class (a value acted upon that isn't bound to what was actually verified). Consequences for the target stack, without any repository write access or valid credentials for that org:
- Forging `status`/`commit_status` events to fabricate successful CI checks on arbitrary commits, which can gate/trigger deploys or merges depending on `Stack` configuration (`ignore_ci`, `continuous_deployment`, `merge_queue_enabled`).
- Forging `push` events to trigger `sync_github` for the victim's stacks, and `check_suite`/`membership`/`pull_request`/`merge` events to manipulate teams, review-stack provisioning, or the merge queue for a repository the attacker has no access to.

This satisfies the High-impact bucket ("escalation into `Shipit.github_teams` authorization" via forged `membership` events, and unauthenticated manipulation of stack/task state via forged CI status) and can contribute toward an unauthorized deploy/merge, which is Critical.

### Likelihood Explanation
Requires: (a) the Shipit deployment is configured with multiple GitHub organizations (a documented, supported configuration), and (b) at least one of those configured organizations has no `webhook_secret` set (also documented as optional) or a leaked/weak one. Given `webhook_secret` is explicitly optional in the setup docs, this is a realistic operational configuration, not a contrived edge case. No authentication, session, or repository access is needed by the attacker — only knowledge of the login of an unprotected configured organization, which is not secret.

### Recommendation
Bind the field used for signature/org selection to the field used for repository resolution: after selecting `repository_owner` and verifying (or explicitly deciding not to verify) the signature, re-derive/require that `payload.dig('repository','full_name')` starts with `"#{repository_owner}/"` before dispatching to handlers, and reject (422) otherwise. Additionally, avoid silently trusting webhooks when `webhook_secret` is blank for any configured organization — either require a `webhook_secret` for every organization or log/alert loudly when running with an unauthenticated organization, since it undermines this binding.

### Proof of Concept
1. Deploy Shipit with two organizations configured, `org-open` (no `webhook_secret`) and `org-victim` (has a `webhook_secret` and owns a tracked `Stack`).
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "org-open" }, "full_name": "org-victim/victim-repo" }
}
```
3. `verify_signature` computes `repository_owner = "org-open"`, looks up `Shipit.github(organization: "org-open")`, and `verify_webhook_signature` returns `true` unconditionally because `org-open` has no `webhook_secret`. [9](#0-8) 
4. `create` dispatches to `StatusHandler`, which uses `sha` only (no repository scoping) to attach a fabricated `success` status to the victim's commit. [8](#0-7) 
5. The forged status can now satisfy `commit.deployable?` checks used elsewhere (e.g. `require_ci` gating in `Api::DeploysController#create`), enabling an unauthorized deploy path for `org-victim`'s stack despite the attacker never holding credentials for that organization. [10](#0-9)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-22)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?
```
