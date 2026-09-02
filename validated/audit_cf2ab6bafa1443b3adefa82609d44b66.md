### Title
Webhook signature is scoped to the GitHub organization, but the event is applied to a repository/commit taken from an unvalidated payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check against using `repository_owner`, a value read straight out of the still-unauthenticated JSON body, and then the request handlers act on a completely different field of the same body (`repository.full_name`, or for `status` events, a bare commit `sha` with no repository scoping at all). Nothing ties the two together, so a valid signature for organization A authorizes writes against any repository/commit that the attacker names elsewhere in the payload.

### Finding Description
`before_action :verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and verifies `request.raw_post` against `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) 

In multi-org installations, each GitHub organization has its own app configuration and its own `webhook_secret`, as documented for `Shipit.github(organization:)` lookups. [2](#0-1) 

Once the signature check passes, `create` dispatches the entire, attacker-controlled JSON body to the registered handler, unmodified:
```ruby
Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [3](#0-2) 

The base `Handler` class resolves the target repository/stack from a *different* field of the same payload:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`repository.owner.login` (used for authentication) and `repository.full_name` (used for authorization/targeting) are two independent JSON leaves inside one request body signed as a single HMAC blob. GitHub itself always keeps them consistent because it generates and signs the payload server-side per installation, but the engine's own code never re-checks that consistency — it only checks that *some* valid secret authenticated the raw bytes, then trusts every other field of those same bytes for targeting. Concretely:

- `PushHandler#process` finds stacks purely via `stacks` (i.e. `repository.full_name`) and triggers `stack.sync_github(expected_head_sha: ...)`. [5](#0-4) 
- `CheckSuiteHandler#process` likewise resolves stacks via `repository.full_name` and schedules `schedule_refresh_check_runs!` for matching commits. [6](#0-5) 
- `StatusHandler#process` is worse: it doesn't even use `repository.full_name` — it matches `Commit.where(sha: params.sha)` **globally**, across every stack in the entire Shipit instance, and writes a GitHub-reported CI state onto it via `create_status_from_github!`. [7](#0-6) 

This is the same class of bug as the GuardCM report: a security check is bound to one attribute of the request (`to == owner`, or here `repository.owner.login`), while the actually-privileged operation is driven by a sibling attribute that the check never constrains (`operation == DelegateCall` to any other target, or here `repository.full_name` / bare `sha`). The equality that should hold — `organization authenticated == organization/repository written` — is never enforced.

### Impact Explanation
Any party that legitimately controls one organization's GitHub App installation on a shared, multi-org Shipit instance (and therefore knows that organization's `webhook_secret`, which is chosen by whoever created that App, per `docs/setup.md`) can POST directly to the public `/webhooks` endpoint with a self-signed, arbitrary JSON body. Because the signature only proves "some valid org secret signed these bytes," not "this payload actually originates from that org's repository," the attacker can set `repository.full_name` to any other org's stack (`push`, `check_suite`) or reference any commit `sha` in the whole install (`status`) and:
- Force `GithubSyncJob`/`sync_github` on a stack they do not own, potentially triggering continuous-deployment behaviour for that stack.
- Forge a passing CI status (`state: success`) on a target commit belonging to an unrelated stack, bypassing the `ci.require` deploy gate documented in `README.md`.
- Trigger `schedule_refresh_check_runs!` against arbitrary commits.

This crosses the "unauthorized deploy" / cross-repository-writes bar the rules define as Critical/High impact, since it lets an org-A-scoped credential holder cause writes and deploy-gate manipulation on org B's stacks that they have no GitHub or Shipit permission over.

### Likelihood Explanation
Requires the attacker to already control (or know the secret of) one organization onboarded into a shared multi-org Shipit deployment — a realistic setup per the engine's own multi-org documentation — and requires the target Shipit instance to actually host stacks for multiple organizations under one webhook endpoint. This is a narrower precondition than a fully unauthenticated attacker, but it is exactly the kind of organization-vs-repository trust-boundary break the analog class targets: no in-app privilege (Shipit session, team membership, `ApiClient` token) is needed, only knowledge of a webhook secret for any one of the participating organizations.

### Recommendation
After signature verification, validate that `repository.owner.login` (or `organization.login`) actually matches the owner segment of `repository.full_name` (and, for `status` events, restrict lookups to commits belonging to stacks under the verified organization) before dispatching to handlers, rather than trusting unrelated payload fields for targeting once any valid secret has been found.

### Proof of Concept
1. Configure Shipit for two orgs, `org-a` and `org-b`, each with its own `webhook_secret` (`S_a`, `S_b`) as shown in `docs/setup.md`.
2. As the party who created/administers `org-a`'s GitHub App (and thus knows `S_a`), craft a `status` webhook body:
```json
{
  "sha": "<sha-of-a-commit-belonging-to-org-b's-stack>",
  "state": "success",
  "repository": { "owner": { "login": "org-a" } }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac(S_a, body)>` and POST it directly to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `org-a`, verifies against `S_a`, and passes.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the org-b commit — and calls `create_status_from_github!`, forging a "success" status on org-b's commit despite the signature only proving knowledge of org-a's secret.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
