### Title
Webhook signature verification keyed on `repository.owner.login` does not bind to the `repository.full_name` actually acted on, allowing cross-repository writes in multi-organization deployments - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate against based on `params.dig('repository', 'owner', 'login')` (or `organization.login`) taken from the *same untrusted payload* whose signature is being checked, but the code path that actually performs writes (`Shipit::Webhooks::Handlers::Handler#repository_name`, used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and the `PullRequest::*` handlers) resolves the target `Repository`/`Stack` from a *different* field: `payload.dig('repository', 'full_name')`. Nothing in the engine enforces that `repository.owner.login` and `repository.full_name`'s owner segment refer to the same organization.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is [2](#0-1) . This chooses which organization's `webhook_secret` (from the multi-org `config/secrets.yml` layout documented in [3](#0-2) ) is used to HMAC-validate the raw body.

Once verification succeeds, `create` dispatches the full, attacker-supplied JSON payload to handlers unmodified [4](#0-3) . Every handler resolves the stacks to mutate via `Handler#repository_name`, which reads a **separate** field of the same payload:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

In a Shipit deployment servicing multiple GitHub organizations (the documented multi-org `github:` config), each organization independently controls and knows its own `webhook_secret` (it is set by whoever administers that org's GitHub App on GitHub's side). Because the signature check trusts `repository.owner.login` from the payload to pick the verification key, and the write path trusts the unrelated `repository.full_name` field from the same payload, an org administrator who legitimately knows their own org's `webhook_secret` can craft an arbitrary raw POST body where `repository.owner.login` == their own org (so the HMAC computed with their own known secret validates), while `repository.full_name` names a repository belonging to a *different* organization also hosted on the same Shipit instance. This breaks the intended binding: **organization authenticated (`repository.owner.login`) ≠ repository written (`repository.full_name`)**.

### Impact Explanation
Depending on handler, this allows an attacker who controls one tenant's webhook secret to inject fabricated GitHub events against another tenant's stacks:
- `PushHandler` calls `stack.sync_github(expected_head_sha:)` for any stack whose branch matches, on repositories resolved purely from the forged `full_name` [6](#0-5)  — this can force a sync/refresh cycle on another organization's stack.
- `StatusHandler` creates fabricated CI statuses on arbitrary commits by sha regardless of which repo they belong to, since `Commit.where(sha:)` is not scoped to the resolved repository at all [7](#0-6) , potentially flipping merge/CI gating state used to unblock deploys or merges for a stack the attacker does not own.
- `CheckSuiteHandler` similarly triggers `schedule_refresh_check_runs!` on another org's commits [8](#0-7) .

If any of these effects can be chained into an unauthorized ship/merge decision (e.g., forged green CI status unblocking an automated merge/deploy gate), this rises to the "unauthorized deploy, rollback or merge" impact tier. At minimum it is a cross-tenant write into stack/commit state that the attacker's organization does not own.

### Likelihood Explanation
This requires the Shipit instance to be configured for **multiple GitHub organizations** (an explicitly documented and supported configuration) and requires the attacker to control (or know) the `webhook_secret` for at least one of those organizations' GitHub Apps — something any admin of that org's GitHub App legitimately has. No GitHub App private key, `GITHUB_TOKEN`, or Shipit session/API token is needed; only knowledge of one tenant's own webhook secret, which is normal knowledge for that tenant's own GitHub App admin. This is a realistic scenario for shared Shipit deployments serving multiple orgs/teams.

### Recommendation
After parsing the payload, derive the authorized organization from `repository_owner` used for signature verification and require that `payload.dig('repository', 'full_name')` (and any repository referenced by handlers) actually belongs to that same organization before dispatching to handlers — i.e., bind the two fields together instead of trusting them independently. Reject the webhook (422) if `repository.full_name`'s owner segment does not match the `repository_owner` that was used to select the verification secret.

### Proof of Concept
1. Configure Shipit (per [3](#0-2) ) with two organizations, `org-a` (attacker-administered) and `org-b` (victim, also hosted on the same Shipit instance), each with its own `webhook_secret`.
2. Attacker, knowing `org-a`'s `webhook_secret`, crafts a raw JSON body for a `push` event:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already known to exist on org-b's stack>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a's webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` looks up `Shipit.github(organization: 'org-a')` (from `repository.owner.login`) and validates successfully since the attacker signed with `org-a`'s real secret [9](#0-8) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name('org-b/victim-repo')` via `repository_name` reading `full_name` [5](#0-4) , and triggers `sync_github` on `org-b`'s stack — an action the attacker, as `org-a` only, should never be able to induce.

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
