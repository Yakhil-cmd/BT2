### Title
Webhook signature verification keys off `repository.owner.login` while every event handler acts on `repository.full_name`, letting a webhook signed for one GitHub App/organization forge events for a different repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate the HMAC signature against based on `repository.owner.login` (falling back to `organization.login`) read directly out of the untrusted JSON body. [1](#0-0)  Every downstream event handler (`PushHandler`, `StatusHandler`, the `PullRequest::*Handler`s), however, resolves the target `Repository`/`Stack` using a *different* field of the same payload: `repository.full_name`. [2](#0-1)  Nothing ties `repository.owner.login` to `repository.full_name` — they are independent, attacker-controlled strings inside the same forged JSON body.

### Finding Description
In a multi-organization Shipit deployment, `secrets.yml` can register several distinct GitHub Apps, one per organization, each with its own `webhook_secret`. [3](#0-2)  `Shipit.github(organization: repository_owner)` looks up the app/secret for whichever organization name is embedded in the payload. [1](#0-0) 

The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization that owns the repository the handler mutates`

An attacker who is the legitimate owner of Organization A (one of the orgs configured in this shared Shipit instance, so they know Org A's real `webhook_secret` because they created that GitHub App) can POST directly to `/webhooks` with:
- `X-Hub-Signature` computed with Org A's `webhook_secret` over the raw body,
- `repository.owner.login` (or `organization.login`) = `"OrgA"` so `verify_signature` picks Org A's app and the signature check passes,
- `repository.full_name` = `"OrgB/victim-repo"`, a completely different, unrelated repository/stack tracked by the same Shipit instance.

`verify_signature` only proves the request was signed with Org A's secret; it never checks that `repository.full_name` actually belongs to Org A. The handler then uses `repository.full_name` to resolve `Stack`/`Commit` records via `Repository.from_github_repo_name` and acts on them:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on every non-archived stack of the *victim* repo/branch with an attacker-chosen `after` SHA. [4](#0-3) 
- `StatusHandler#process` creates arbitrary, attacker-chosen commit statuses (state/description/target_url/context) on any existing commit SHA it names, regardless of which repo it belongs to. [5](#0-4) 

Because `Repository.from_github_repo_name` performs a simple owner/name lookup with no cross-check against the organization that validated the signature, the resolved `Stack`/`Repository`/`Commit` can belong to any organization tracked by the Shipit instance. [6](#0-5) 

### Impact Explanation
Spoofed `status` events let an attacker who only controls one onboarded organization's GitHub App forge passing CI statuses on another organization's commits. If that victim stack's `shipit.yml` requires those statuses for continuous deployment/merge, this can be used to bypass CI gating and trigger an unauthorized deploy or merge on a repository the attacker does not control — matching the "unauthorized deploy, rollback or merge" / cross-repository-write impact bar. Spoofed `push` events force `sync_github` on the victim's stack/branch with an attacker-chosen `after` SHA, corrupting the tracked HEAD used for continuous deployment decisions on a repository outside the attacker's control.

### Likelihood Explanation
This requires the attacker to be a legitimate administrator of at least one organization that is genuinely configured in the same multi-organization Shipit installation (so they know that organization's real `webhook_secret`), and requires that installation to track more than one organization/repository. This is a non-trivial but realistic operating model explicitly documented as supported ("Using Multiple GitHub Applications"). No GitHub App private key, `ApiClient` token, or Shipit session is needed — only knowledge of one legitimately-owned org's webhook secret plus the ability to send an arbitrary HTTP POST to the public `/webhooks` endpoint, which is unauthenticated by design (it's authenticated only via the HMAC signature).

### Recommendation
After selecting the GitHub App via `repository_owner`, cross-check that the resolved repository's actual owner (as known/stored in Shipit's `Repository` table, or as derived consistently from `repository.full_name`) matches the organization whose secret validated the signature, and reject the webhook if they diverge. Alternatively, derive the app-selection key from the same field (`repository.full_name`'s owner segment) that handlers use to resolve the target repository, so the same value is both signed-over and acted-upon.

### Proof of Concept
1. Configure/observe a Shipit instance tracking at least two organizations, `OrgA` (attacker-owned, attacker knows its GitHub App `webhook_secret`) and `OrgB` (victim, has a stack tracked by Shipit with continuous deployment / required statuses).
2. Craft a `status` webhook JSON body:
```json
{
  "sha": "<victim commit sha the attacker wants to mark green>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, raw_body)>`.
4. `POST /webhooks` with header `X-Github-Event: status` and the above body/signature.
5. `verify_signature` resolves the GitHub App via `repository.owner.login = "OrgA"`, verifies successfully with OrgA's secret. [1](#0-0) 
6. `StatusHandler` looks up commits by `params.sha` (independent of any org check) and creates a forged `success` status on the victim's commit, potentially unblocking a deploy/merge gate on `OrgB/victim-repo`. [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
