### Title
Cross-repository forged CI status via unscoped `sha` lookup in webhook `status` handler - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The bug class in the report is "incorrect input validation": a value used to authorize an action is not the same value that action actually operates on. In Shipit's webhook pipeline the equality that must hold is:

`organization whose webhook_secret verified the request == organization/repository that owns the data being mutated`

`StatusHandler` breaks this equality: it writes a GitHub commit status to **any** `Commit` row in the database that matches the attacker-supplied `sha`, with no check that the commit belongs to the repository/organization whose `webhook_secret` was used to authenticate the request.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC against based on `repository_owner`, which is read straight out of the untrusted JSON payload (`repository.owner.login` or, as a fallback, `organization.login`): [1](#0-0) [2](#0-1) 

Once the signature is accepted, the full raw payload is dispatched to the matching handler(s): [3](#0-2) 

`StatusHandler#process` then looks up commits **purely by `sha`**, with no scoping to the repository/organization that authenticated the request: [4](#0-3) 

Compare this to `PushHandler` and `CheckSuiteHandler`, which correctly scope their side effects through `Handler#stacks`, itself derived from `payload.dig('repository', 'full_name')`: [5](#0-4) [6](#0-5) 

`StatusHandler` has no such scoping — `Commit.where(sha: params.sha)` matches globally across every repository/stack hosted on the Shipit instance, and Shipit explicitly supports multiple GitHub organizations, each with its own `webhook_secret`, on a single instance: [7](#0-6) 

Because Shipit deployment gating (`ci.require` / commit `deployable?`) is driven by these `Status` rows, this breaks the binding "organization that authenticated == repository whose CI state is written": an attacker who legitimately administers Org A's GitHub App (and therefore legitimately knows/controls Org A's `webhook_secret`) can send a signed `status` webhook using Org A's secret but with a `sha` value that happens to belong to a commit under a totally unrelated Org B's stack hosted on the same Shipit instance, and successfully forge that commit's CI status.

### Impact Explanation
This is a cross-repository/cross-organization write into the CI status ledger of a stack the attacker has no privileges over. If the forged status satisfies a `ci.require` context for that foreign stack, it can help make an otherwise CI-failing (or never-tested) commit appear `deployable?`, contributing to an unauthorized deploy on a repository the attacker doesn't control — this matches the "Critical: cross-repository writes / unauthorized deploy" impact bucket, since the write crosses the authentication boundary established by `webhook_secret`/organization scoping.

### Likelihood Explanation
Requires the attacker to legitimately administer at least one GitHub organization/App installation that is onboarded to the shared Shipit instance (a scenario explicitly supported and documented by Shipit's multi-org `github:` config), plus knowledge of a target `sha` in another org's stack (SHAs are not secret — they're visible on GitHub / in Shipit's own UI). No privileged Shipit account, session, or `ApiClient` token is needed; the entire webhook is self-signed by the attacker with a secret they legitimately hold for their own org.

### Recommendation
Scope `StatusHandler#process` to commits belonging to the repository identified in the payload (as `PushHandler`/`CheckSuiteHandler` already do via `Handler#stacks`/`repository_name`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)`, rather than a global `Commit.where(sha: ...)` lookup.

### Proof of Concept
1. Attacker administers `OrgA`'s GitHub App on a shared multi-tenant Shipit instance (config has both `OrgA` and `OrgB` under `github:`), and thus knows `OrgA`'s `webhook_secret`.
2. Attacker learns the `sha` of a commit belonging to a stack under `OrgB/some-repo` (public info).
3. Attacker computes `sha1=HMAC(OrgA_webhook_secret, body)` over a crafted JSON body:
```json
{"sha": "<OrgB commit sha>", "state": "success", "context": "required-ci-check", "target_url": "https://evil"}
```
4. POST to `/webhooks` with `X-Github-Event: status` and `X-Hub-Signature` set to that HMAC.
5. `WebhooksController#verify_signature` resolves `repository_owner` from the (attacker-omitted) `repository`/`organization` fields — falling back or using `OrgA` — and validates successfully against `OrgA`'s secret [1](#0-0) .
6. `StatusHandler#process` matches the commit purely by `sha` in `OrgB`'s repository and writes the forged status [4](#0-3) , with no verification that the commit belongs to `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
