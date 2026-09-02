### Title
Cross-organization webhook forgery: signature verified against one organization while the write target is resolved from an unrelated attacker-controlled field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which HMAC `webhook_secret`) to validate a webhook against using `repository_owner`, which is read from `repository.owner.login` (falling back to `organization.login`) in the JSON body. [1](#0-0) [2](#0-1)  Once the signature check passes, the actual event handler (e.g. `PushHandler`, `CheckSuiteHandler`) resolves the `Stack`/`Repository` it acts on from a completely different field of the same body: `payload.dig('repository', 'full_name')`, via `Handler#repository_name`/`Handler#stacks`. [3](#0-2)  Nothing enforces that `repository.owner.login` (used to pick the signing secret) and `repository.full_name` (used to pick the object that gets written to) refer to the same organization.

### Finding Description
Shipit explicitly supports hosting multiple GitHub organizations from a single instance, each configured with its own `webhook_secret` under a per-organization key in `config/secrets.yml`. [4](#0-3)  Any principal who legitimately owns/administers one such organization ("OrgA") in the shared instance knows OrgA's `webhook_secret` (they configured it themselves when creating the GitHub App), because it must be supplied in clear text during setup.

The verification binding is:
```
Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_body)
```
where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`. [1](#0-0) [2](#0-1) 

The write binding, used moments later by the dispatched handler, is:
```
Repository.from_github_repo_name(payload.dig('repository','full_name'))
``` [3](#0-2) 

These two lookups read two independent JSON keys (`repository.owner.login` vs `repository.full_name`) that are never cross-validated against each other. An OrgA administrator can craft a raw JSON body such as:
```json
{
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"},
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
sign it with OrgA's own known `webhook_secret` (HMAC-SHA1 over the raw body, `X-Hub-Signature: sha1=...`), and POST it to `/webhooks` with `X-Github-Event: push`. `verify_signature` looks up `Shipit.github(organization: "OrgA")`, validates successfully because the attacker used OrgA's real secret, [1](#0-0)  and then `PushHandler#process` resolves stacks belonging to `OrgB/target-repo` (a repository/stack the attacker has no relationship with) and calls `stack.sync_github(expected_head_sha: params.after)` on it. [5](#0-4)  The same mismatch applies to `CheckSuiteHandler`, which schedules `schedule_refresh_check_runs!` on commits belonging to the resolved (attacker-chosen) stack. [6](#0-5) 

Root cause: the equality the code should enforce — "organization whose secret authenticated the request" == "organization/repository the handler is permitted to act on" — is never checked. The signature-selection key (`repository.owner.login`/`organization.login`) and the action-target key (`repository.full_name`) are disjoint fields inside the same attacker-supplied JSON payload.

### Impact Explanation
This breaks the tenant-isolation boundary between organizations hosted on the same Shipit instance: an admin of OrgA, holding only OrgA's own webhook secret, can forge webhook deliveries that are processed as if they targeted OrgB's stacks. For `push` events this causes an unsolicited `sync_github`/`GithubSyncJob` invocation against another organization's stack with an attacker-influenced `expected_head_sha`, and for stacks with `continuous_deployment` enabled this can be used to force resync/deploy cycles on a schedule the attacker controls — an unauthorized cross-repository action against a stack the attacker has no legitimate access to. This maps to the "cross-repository writes / unauthorized deploy" Critical impact category, since the attacker never authenticated as, nor was granted any permission by, OrgB.

### Likelihood Explanation
Exploitation requires the attacker to control (own/administer) at least one organization hosted on the shared Shipit installation — i.e. know that organization's own legitimately-provisioned `webhook_secret` — which is a realistic, unprivileged-with-respect-to-other-tenants position in the documented multi-organization deployment model. [4](#0-3)  No GitHub App private key, no Shipit session, and no ApiClient token for the victim organization are needed; only knowledge of one's own webhook secret and the ability to POST an HTTP request to `/webhooks`.

### Recommendation
Bind the signature-verification organization to the same field used to resolve the write target. Concretely, derive `repository_owner` from the same `repository.full_name` (or vice versa) that `Handler#repository_name` uses, and reject the webhook if `repository.owner.login`/`organization.login` does not match the owner segment of `repository.full_name`. Alternatively, after signature verification, re-verify inside `Handler` (or a shared before-hook) that the resolved `Repository`'s owner matches the organization whose secret validated the request before any handler is allowed to mutate state.

### Proof of Concept
1. Attacker administers `OrgA` on a shared Shipit instance (per the documented multi-org setup) and knows `OrgA`'s `webhook_secret`.
2. Attacker crafts:
```json
{"repository":{"owner":{"login":"OrgA"},"full_name":"OrgB/target-repo"},"ref":"refs/heads/master","after":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and succeeds. [1](#0-0) 
5. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/target-repo")` and invokes `stack.sync_github(expected_head_sha: "deadbeef...")` on OrgB's stack, despite the request never being authenticated against OrgB's secret. [5](#0-4) [3](#0-2)

### Citations

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
