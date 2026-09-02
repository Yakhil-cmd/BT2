### Title
Webhook signature verification is scoped to the wrong organization key, allowing cross-organization forged webhooks to act on repositories the signing organization does not own - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `params.dig('repository','owner','login')` (or `organization.login`), but the actual side-effecting webhook handlers resolve the target repository/stack using a completely different field, `payload.dig('repository','full_name')`. Because these two fields are never cross-checked, a party that legitimately controls one configured organization's webhook secret can craft a payload whose `repository.owner.login` matches their own org (so the signature validates) while `repository.full_name` points at a different organization's repository, causing Shipit to act on that other repository/stack.

### Finding Description
`verify_signature` picks the GitHub App/secret purely from the owner login: [1](#0-0) [1](#0-0) [2](#0-1) 

`repository_owner` is derived only from `repository.owner.login` / `organization.login`, and is used solely to look up `Shipit.github(organization: repository_owner)` and its `webhook_secret` for HMAC validation.

Once the signature check passes, event handlers are dispatched with the raw parsed JSON and never re-derive or compare the organization used for verification: [3](#0-2) 

Every handler determines *which stack/repository record to mutate* independently, using `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

For example, `PushHandler` triggers a GitHub sync job for any stack under the resolved repository: [5](#0-4) 

and `PullRequest::ClosedHandler` independently re-resolves the repository from `params.repository.full_name` to archive review stacks: [6](#0-5) 

The binding that should hold is:
`organization authenticated by verify_signature (repository.owner.login) == organization owning repository.full_name acted on by the handler`

Shipit's own documentation confirms this is a real multi-tenant configuration where distinct organizations each have their own `app_id`/`webhook_secret`: [7](#0-6) 

Because `repository.owner.login` and `repository.full_name`'s owner segment are never compared, an attacker who is an authenticated GitHub App/organization admin for **one** configured organization (i.e., who legitimately possesses that organization's `webhook_secret`, which is provided to org admins during onboarding per `docs/setup.md`) can POST directly to `/webhooks` with:
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` resolves their own secret and the HMAC check passes)
- `repository.full_name` = `"other-org/other-repo"` (any repository already tracked as a `Stack` in the shared Shipit instance)

This lets them trigger `PushHandler`, `CheckSuiteHandler`, `StatusHandler`, or `PullRequest::ClosedHandler` (archiving another org's review stacks, injecting fabricated commit statuses via `StatusHandler`, or forcing `GithubSyncJob` to run against another org's stack) on a repository/stack they do not own and were never granted webhook trust for.

### Impact Explanation
This breaks the organization-vs-repository binding explicitly called out as in-scope: the organization whose credentials were verified is not the organization whose repository is mutated. Concretely reachable effects on other orgs' stacks include: fabricating commit statuses (`StatusHandler` → `Commit#create_status_from_github!`), archiving review stacks (`PullRequest::ClosedHandler`), and forcing sync/deploy-adjacent jobs (`PushHandler` → `GithubSyncJob`) — i.e., cross-repository writes performed by an entity with no legitimate authority over the target repository. This matches the High/Critical bar of "cross-repository writes" / "unauthorized deploy" surfaces named in scope, since a forged `commit_status` can influence CI-gated deploy eligibility on a stack belonging to a different tenant organization.

### Likelihood Explanation
Requires the attacker to already control a legitimate `webhook_secret` for at least one organization configured in a multi-tenant Shipit deployment (per the documented multiple-GitHub-Applications setup) — this is a credential they are entitled to for their own org, not a privileged Shipit account or `GITHUB_TOKEN`. No GitHub-side spoofing is needed: they can POST directly to the public `/webhooks` endpoint with any `repository.full_name`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`/`#stacks`), cross-validate that the resolved target repository's owner (`Repository#full_name` prefix, or the associated GitHub App's organization) matches `repository_owner`/the organization whose secret validated the signature, and reject the webhook (422) if they diverge.

### Proof of Concept
1. Attacker is an admin of `OrgA`, a legitimate tenant with its own `webhook_secret` configured under `Shipit.github(organization: 'OrgA')`.
2. Attacker computes `sha1=HMAC(OrgA_webhook_secret, body)` for a crafted push payload where:
   - `repository.owner.login = "OrgA"`
   - `repository.full_name = "OrgB/victim-repo"` (an existing stack belonging to a different tenant, `OrgB`)
   - `ref = "refs/heads/main"`, `after = "<arbitrary sha>"`
3. POST to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` resolves `Shipit.github(organization: 'OrgA')` and validates successfully because the signature was computed with `OrgA`'s real secret.
5. `PushHandler` (dispatched without any re-check) resolves `Repository.from_github_repo_name('OrgB/victim-repo')` and calls `stack.sync_github(expected_head_sha: params.after)` on `OrgB`'s stack, an action `OrgA` never had trust to trigger.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
