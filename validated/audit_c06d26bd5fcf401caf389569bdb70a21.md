### Title
Cross-organization webhook signature confusion via mismatched `repository.owner.login` vs `repository.full_name` fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the inbound webhook's HMAC signature against using `repository.owner.login` (falling back to `organization.login`), but the event handlers that actually act on the payload (`Handler#repository_name` and its subclasses) resolve the target `Repository`/`Stack` using an entirely different field, `repository.full_name`. Because these are two independent, attacker-controlled fields inside the same signed JSON body, a party who legitimately administers one organization configured in Shipit's multi-org `secrets.github` map (and therefore knows that organization's `webhook_secret`, since they configured it themselves) can forge a payload whose signature is valid for their own org but whose `repository.full_name` points at a stack belonging to a different, unrelated organization also hosted on the same Shipit instance.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and uses it to pick the `GitHubApp` instance (and its `webhook_secret`) to check the signature against: [1](#0-0) [2](#0-1) 

Once the signature check passes, `create` dispatches the same raw `params` hash to the matching handler(s): [3](#0-2) 

Every handler resolves the target repository/stacks not from `repository.owner.login` (the field used for signature-key selection) but from `repository.full_name`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits `full_name` on `/` and looks up any repository/owner pair in the database, with no cross-check against the org that authenticated the request: [5](#0-4) 

`PushHandler`, `StatusHandler`, and `CheckSuiteHandler` all act on whatever stacks/commits that lookup returns: [6](#0-5) [7](#0-6) [8](#0-7) 

Shipit explicitly supports hosting multiple independent GitHub organizations, each with its own `app_id`/`webhook_secret`/`private_key`, in a single instance's secrets file: [9](#0-8) 

The equality the engine is supposed to preserve is:
`organization that authenticated the request` == `organization/repository whose state the handler mutates`

Because signature verification keys off `repository.owner.login`/`organization.login` while every downstream handler keys off the independent `repository.full_name` field, this equality is not enforced anywhere. An org administrator for Org A (who legitimately possesses Org A's `webhook_secret` because they configured Shipit's GitHub App for their own org) can sign a payload with Org A's secret while setting `repository.full_name` to `OrgB/some-repo`, causing Shipit to treat the forged, cross-org payload as authentic for Org B's stacks.

### Impact Explanation
This breaks the trust boundary between organizations hosted on the same Shipit instance: an attacker with control over only one (lower-privilege) organization's webhook secret can inject forged `push`, `status`, or `check_suite` events for a stack owned by a completely different organization. Concretely:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: ...)` for every matching stack, letting the attacker drive another org's stack's known-HEAD state and downstream deploy-eligibility logic with forged data — a cross-repository write across organizations.
- `StatusHandler#process` lets the attacker create arbitrary commit statuses (`commit.create_status_from_github!`) on commits belonging to another org's stack, which can be used to spoof CI/deploy-safety signals (`status.context`, `deploy.max_commits`, lock/safety checks) that gate whether a deploy is allowed to proceed — enabling an unauthorized deploy.
- `CheckSuiteHandler#process` can trigger check-run refreshes against another org's commits.

This satisfies the Critical/High bar of "cross-repository writes" and potentially "an unauthorized deploy" via forged status/commit state, achieved purely through crafting an HTTP request with a valid signature for an org the attacker legitimately controls — no privileged Shipit session, `ApiClient` token, or GitHub App private key for the *target* org is required.

### Likelihood Explanation
Exploitability requires only that Shipit be configured to serve multiple GitHub organizations (a documented, supported configuration — see `secrets_double_github_app.yml`) and that the attacker be a legitimate administrator of at least one of them (a low bar, since organizations can be added to a shared Shipit instance for many reasons, including by less-trusted teams). No knowledge of another org's `webhook_secret`, private key, or Shipit credentials is needed — only the ability to compute an HMAC with a secret the attacker already owns, and to freely choose the `repository.full_name` field independent of `repository.owner.login`.

### Recommendation
Enforce that the organization used to select/verify the webhook signature is the same organization the acted-upon repository belongs to. Concretely, in `Handler#repository_name` (or in `WebhooksController#create`), validate that the `owner` component of `repository.full_name` matches `repository.owner.login`/`organization.login` used in `verify_signature`, and reject (422) any payload where they diverge. Alternatively, pass the already-resolved `repository_owner`/`github_app` from the controller into each handler and require handlers to scope repository lookups (`Repository.from_github_repo_name`) to that verified owner rather than trusting `full_name` alone.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `OrgA` (attacker-administered, `webhook_secret: sA`) and `OrgB` (victim org, some stack `OrgB/app`), as in `test/dummy/config/secrets_double_github_app.yml`.
2. As an OrgA admin, build a `push` payload body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/app"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(sA, body)>` using OrgA's known `webhook_secret`.
4. POST this to `/github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and verifies the signature successfully against `sA`.
6. `PushHandler#process` resolves `repository_name` from `repository.full_name` = `"OrgB/app"`, finds `OrgB`'s stack via `Repository.from_github_repo_name`, and calls `sync_github(expected_head_sha: params.after)` on it — mutating OrgB's stack state using a signature the attacker forged with an unrelated organization's secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
