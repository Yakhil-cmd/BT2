### Title
Webhook signature is verified against the organization named in the payload, not against the repository the payload's handlers actually write to - cross-organization write forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization secret to use for HMAC verification from an attacker-controlled field inside the very payload it is about to verify (`repository.owner.login` or `organization.login`). Once verification passes, every `Shipit::Webhooks::Handlers::Handler` subclass resolves the *target* stack from a *different* field of the same payload, `repository.full_name` [1](#0-0) , with no check that this repository belongs to the organization whose secret validated the signature. This breaks the intended binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` derives the org used to look up the webhook secret purely from the request body: [2](#0-1) [3](#0-2) 

`Shipit::GithubApp#verify_webhook_signature` only checks that the HMAC over the *entire raw body* matches the secret configured for that organization key; it says nothing about which repository the payload claims to describe: [4](#0-3) 

Shipit explicitly supports hosting multiple, independent GitHub organizations from one deployment, each with its own `webhook_secret` in `secrets.yml`: [5](#0-4) 

After signature verification succeeds, the base `Handler` class (used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, membership/pull-request handlers, etc.) resolves the stacks to act on using `payload.dig('repository', 'full_name')`, a field that is never checked against `repository_owner`/`organization.login` used for the signature lookup: [1](#0-0) 

Because both fields (`repository.owner.login` and `repository.full_name`) live in the same JSON body that the attacker fully controls when crafting a raw POST to `/webhooks`, an org whose own webhook secret is legitimately known to its members (they configured it when installing the GitHub App on their own org) can:
1. Set `repository.owner.login` = their own org (`orgA`) so `verify_signature` looks up and validates against `orgA`'s secret — which they possess.
2. Set `repository.full_name` = `"orgB/some-repo"`, an entirely different, unrelated organization's repository that Shipit also hosts on the same instance.

The HMAC only proves the body came from someone who knows `orgA`'s secret; it does not prove the body's `repository.full_name` field is actually owned by `orgA`. This is the same class of defect as the audited `_getPositionTVL()` bug: a value used for authorization/accounting (the LP stake) is decoupled from the value actually representing the full position/binding (staked + reward exposure) — here, the value used to select the signing secret (`repository.owner.login`) is decoupled from the value actually acted upon (`repository.full_name`).

### Impact Explanation
This yields cross-repository/cross-organization writes with an attacker who has no privileges on the victim org at all, satisfying the Critical impact bar ("cross-repository writes"):
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every not-archived stack on the victim's branch, letting the attacker trigger commit sync/lookup activity for `orgB`'s stacks on demand: [6](#0-5) 
- `StatusHandler#process` calls `commit.create_status_from_github!(params)` for any commit `sha` known to the attacker (SHAs are public GitHub data), letting them inject/spoof fabricated CI/commit statuses for `orgB`'s commits — statuses that Shipit's deploy-safety gating (`require_ci`, deployability checks) relies on: [7](#0-6) 
- `CheckSuiteHandler#process` similarly schedules check-run refreshes for `orgB` commits: [8](#0-7) 

Since deployability/CI-gating status is one of the signals `Shipit::Api::DeploysController#create` relies on (`require_ci` + `commit.deployable?`), forging a passing status for `orgB`'s commit from `orgA`'s trusted webhook channel can facilitate downstream unauthorized deploys of `orgB`'s stacks: [9](#0-8) 

### Likelihood Explanation
Requires only that the Shipit deployment host more than one GitHub organization (an explicitly supported and documented multi-org configuration), and that the attacker be a legitimate member/admin of one of those organizations who knows that org's own `webhook_secret` (which they set up themselves) — no access to `orgB` or to Shipit's admin credentials is needed. The attacker crafts a raw HTTP POST directly to `/webhooks` (bypassing GitHub entirely), so likelihood is high in any multi-tenant Shipit installation.

### Recommendation
After signature verification, re-derive the acting organization from the *same* field used to select the secret (or vice versa) and assert they match before dispatching to handlers — e.g., verify that `payload.dig('repository', 'full_name')` starts with the org used in `repository_owner`, or better, look up the `Repository`/`Stack` and confirm its stored `owner`/organization matches `repository_owner` before calling any handler in `WebhooksController#create`.

### Proof of Concept
1. Shipit instance configured with two orgs in `secrets.yml`: `orgA` (secret `SA`) and `orgB` (secret `SB`), each with stacks registered in Shipit.
2. Attacker, a member of `orgA`, knows `SA` (they configured it on GitHub for their own app installation).
3. Attacker crafts JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<known head sha of orgB/some-repo>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/some-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(SA, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `Shipit.github(organization: "orgA")`, and the HMAC validates successfully against `SA`.
6. `PushHandler.process` runs `Handler#repository_name` = `payload.dig('repository', 'full_name')` = `"orgB/some-repo"`, resolves `orgB`'s stacks, and triggers `sync_github` on them — activity the attacker had no authorization to trigger, entirely from knowledge of `orgA`'s own webhook secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-27)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
```
