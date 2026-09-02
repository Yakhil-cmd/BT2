### Title
Unscoped commit lookup in `StatusHandler` breaks the organization-authenticated-vs-repository-written binding, enabling cross-repository forged commit statuses - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a webhook against the GitHub App installed for a *specific organization*, derived from the payload's `repository.owner.login` (or `organization.login`) field. [1](#0-0)  That verification only proves the request was signed by that one organization's `webhook_secret` — Shipit explicitly supports multiple, independently-configured GitHub Apps/organizations sharing the same instance. [2](#0-1) 

The `status` event is then dispatched to `StatusHandler`, which — unlike other handlers — never re-derives or checks the repository the commit belongs to. It resolves the target purely by SHA, globally across the entire installation:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

Compare this to `PushHandler`, which correctly scopes writes to stacks belonging to the payload's own repository via the base `Handler#stacks` helper:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) [5](#0-4) 

`StatusHandler` skips this `stacks`/`repository_name` scoping entirely, so the signed `repository.owner.login` used to select the verifying webhook secret has no relationship whatsoever to which `Commit` row actually gets mutated.

### Finding Description
This is the same class of bug as the YToken report: a field that is authorized/verified (the organization identity behind the signature) is not the same field that is acted upon (the target commit/repository whose status is written). The binding that should hold is:

`organization authenticated by signature == repository owning the commit whose status is mutated`

Before the attacker's request: a commit `C` with sha `S` exists as part of stack/repository `org-victim/repo-victim`, tracked by this Shipit instance. `C` has no successful status yet (or a pending/failing one required by CI gating).

The attacker controls a legitimate, but unrelated, installation: `org-attacker/repo-attacker`, also configured in this multi-org Shipit deployment (a supported and documented configuration). [6](#0-5)  They can trigger a real `status` webhook from GitHub for their own repo (e.g., by pushing a commit and having their own CI post a status, or by using any integration attached to their own repo that can set commit statuses) — no Shipit/API-client credentials are needed, only ordinary GitHub write access to their own repository. GitHub signs this payload with `org-attacker`'s webhook secret, and it passes `verify_webhook_signature` for `org-attacker`. [7](#0-6) 

The payload only needs a `sha` field, which the attacker fully controls in the underlying request the CI/integration constructs (or, if the attacker has push access replayable to any sha, they choose `S`, the victim's commit hash — public commit SHAs are trivially knowable). Once `verify_signature` passes (because it validated against `org-attacker`'s own secret, a check that has nothing to do with the `sha` field), `StatusHandler.process` runs `Commit.where(sha: params.sha)`, finds the victim's `Commit` row for `org-victim/repo-victim`, and calls `commit.create_status_from_github!(params)`, writing an attacker-chosen state/context onto a commit in a repository the attacker has no access to.

After the request: commit `C` in `org-victim/repo-victim` now carries a forged status (e.g., `state: "success"`) even though `org-attacker` never authenticated for, nor was ever granted any privilege over, `org-victim/repo-victim`.

### Impact Explanation
Commit statuses feed directly into Shipit's deployability gating (`Stack#deployable?` / `deployment_checks_passed?`) and continuous-deployment logic. [8](#0-7)  A forged `success` status injected via this cross-tenant write can satisfy required-status checks for `org-victim`'s stack, allowing continuous delivery to proceed to an unauthorized deploy the victim organization never approved — this lands squarely in the "unauthorized deploy" Critical impact bucket. At minimum it corrupts commit state/CI history that stack maintainers rely on to decide whether to ship.

### Likelihood Explanation
Likelihood is high in any multi-organization Shipit deployment (an explicitly documented and supported configuration). [6](#0-5)  The only prerequisite is that the attacker controls (or can trigger events for) one organization/repository already onboarded to the shared Shipit instance — no elevated Shipit permissions, `ApiClient` tokens, or GitHub App keys for the victim org are required, satisfying the "unprivileged attacker" constraint.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup to the repository identified in the same signed payload (mirroring `Handler#stacks`/`repository_name`), e.g. join through `Commit -> Stack -> Repository` and filter by `repository_name == payload.dig('repository', 'full_name')` before calling `create_status_from_github!`. Reject or ignore statuses whose SHA does not belong to a stack under the authenticated repository/organization.

### Proof of Concept
1. Configure Shipit with two organizations, `org-attacker` and `org-victim`, each with its own GitHub App/`webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications").
2. Note a tracked commit `sha=S` belonging to a stack under `org-victim/repo-victim` (SHAs are public).
3. From `org-attacker`'s installation, send a `status` webhook (`X-Github-Event: status`) whose body sets `"sha": "S"`, `"state": "success"`, `"repository": {"owner": {"login": "org-attacker"}, ...}`, signed with `org-attacker`'s webhook secret.
4. `WebhooksController#verify_signature` succeeds because it verifies against `org-attacker`'s secret only. [1](#0-0) 
5. `StatusHandler#process` executes `Commit.where(sha: "S")`, finds the victim's commit, and writes the forged `success` status onto it. [3](#0-2) 
6. Observe `org-victim/repo-victim`'s deployment gating now reflects the forged status, potentially unblocking/triggering an unauthorized deploy.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/stack.rb (L376-378)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
    end
```
