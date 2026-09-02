### Title
Cross-organization webhook forgery via signature/subject mismatch in `WebhooksController` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to validate the `X-Hub-Signature` based on `repository.owner.login` (falling back to `organization.login`) pulled directly out of the untrusted request body, but the webhook handlers that actually act on the payload (via `Handler#stacks`/`Handler#repository_name`) key off a *different* field, `repository.full_name`. This is structurally identical to the Frankencoin bug class: a field that determines the "authorized" identity (`repository_owner`, which selects the signing secret) is never bound to the field that determines what gets *written* (`repository.full_name`, which selects the `Stack`/`Repository` acted upon).

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 

where
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Once the signature check passes, `create` dispatches the same raw JSON to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Every handler resolves the target `Stack`/`Repository` through a completely independent field:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

Shipit explicitly supports hosting multiple GitHub organizations from a single instance, each with its own `app_id`/`webhook_secret` [5](#0-4) . In that configuration, a party who legitimately controls one organization's GitHub App (and therefore knows that organization's `webhook_secret`) can craft an arbitrary JSON body where `repository.owner.login` names *their own* organization (so the HMAC check passes using their own secret) while `repository.full_name` names a repository belonging to a *different* organization hosted on the same Shipit instance. The controller has no code path that cross-checks that the organization used to select the verifying secret is the same organization that owns the repository the handlers subsequently act on.

Concretely: `StatusHandler#process` looks up `Commit.where(sha: params.sha)` globally (not scoped by the signing org at all) and writes a status [6](#0-5) , and `PushHandler#process` resolves stacks via `Handler#stacks` (i.e., via `repository.full_name`) and triggers `stack.sync_github` [7](#0-6) . Neither of these (nor the `pull_request`/`membership`/`check_suite` handlers, all of which resolve via `repository.full_name` or `organization.login` taken straight from the body) ever re-derives or compares against `repository_owner`, the field that was actually authenticated.

### Impact Explanation
An org admin/integrator who is fully authorized only for **their own** GitHub organization/App on a shared Shipit instance can forge signed webhook deliveries that are attributed to and acted on for a **different** organization's stacks that they have no privileges over. Depending on event type this allows:
- Injecting forged commit `Status` records for arbitrary commit SHAs system-wide (`StatusHandler`), which `MergeRequest`/`StatusChecker` logic uses to gate merges and deploys — a path to bypassing CI requirements and triggering an unauthorized merge/deploy for a repository the attacker does not control.
- Forcing `GithubSyncJob`/`RefreshCheckRunsJob` runs against another org's stacks (`PushHandler`, `CheckSuiteHandler`).
- Archiving/unarchiving another org's review stacks via forged `pull_request` label events.
- Creating/removing team memberships cross-tenant via the `membership` handler.

This crosses the "organization that authenticated vs. the repository that is written" trust boundary called out for this scan, and the strongest instance of it (forged CI status enabling an unauthorized merge) meets the Critical/High bar for unauthorized deploy/merge.

### Likelihood Explanation
Requires the attacker to already control one legitimate GitHub App installation/webhook secret on the shared Shipit instance — this is a real, documented multi-tenant configuration (`docs/setup.md`, "Using Multiple Github Applications"), so it is plausible in any Shipit deployment serving more than one organization, without requiring compromise of the target organization's own credentials.

### Recommendation
Bind the field used to select/verify the signing secret to the field used to resolve the target repository/stack: after verifying the signature, re-derive `repository_owner` from the *same* `repository.full_name` value the handlers will use (or vice versa), and reject the request if they disagree (e.g., `repository.full_name.split('/').first.downcase != repository_owner.downcase`). Alternatively, pass the verified `repository_owner`/organization into the handler layer and have `Handler#stacks` scope its `Repository.from_github_repo_name` lookup to repositories owned by the verified organization.

### Proof of Concept
1. Shipit instance is configured with two orgs, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md` multi-org setup) and each hosting stacks tracked by Shipit.
2. An attacker who administers `org-a`'s GitHub App (and thus knows `org-a`'s `webhook_secret`) crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/target-repo" }
}
```
3. Attacker computes `X-Hub-Signature` as `sha1=HMAC(org-a-webhook-secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` and validates successfully because the attacker's HMAC matches `org-a`'s secret [1](#0-0) .
5. `create` dispatches to `PushHandler`, which resolves `stacks` via `repository.full_name = "org-b/target-repo"` [8](#0-7)  and calls `sync_github` on `org-b`'s stack — an action the attacker has no authorization to trigger.

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
