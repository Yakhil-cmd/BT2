### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the target `Stack`/`Repository` is resolved from the unrelated `repository.full_name` field — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against using one field of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`), while every event `Handler` (`PushHandler`, `CheckSuiteHandler`, and any handler using `Handler#stacks`) resolves the `Repository`/`Stack` that gets mutated using a *different* field of that same untrusted body: `repository.full_name`. These two fields are never checked for consistency, so a signature that is valid for organization A does not guarantee the payload's effects are scoped to organization A's repositories.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization purely from the request body: [1](#0-0) [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This selects the `GitHubApp`/webhook secret via `Shipit.github(organization: repository_owner)` [3](#0-2)  — this is the "engine's" identity binding for **which org authenticated the request**.

Once `verify_signature` passes, `create` hands the *entire raw payload* to every registered handler for the event: [4](#0-3) 

Handlers determine **which repository/stack is written to** using a completely different key of the same JSON body: [5](#0-4) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler#process` and `CheckSuiteHandler#process` then act on `stacks` (triggering `stack.sync_github`, `schedule_refresh_check_runs!`, etc.) using this `full_name`-derived repository, not the `repository.owner.login` used for signing: [6](#0-5) [7](#0-6) 

This is structurally the same class of bug as the report's binary-search mismatch: two different code paths use two different fields of the same input to answer what should be the same question ("which org/timestamp is this?"), and nothing enforces they agree. Here the broken equality is:

`organization whose secret authenticated the payload` == `owner of the repository whose Stack is written by the payload`

Concretely, `repository.owner.login` and `repository.full_name`'s owner segment are independent, attacker-controlled JSON keys with no cross-validation. A party who legitimately administers the GitHub App/webhook for organization **A** (and thus can compute a valid `X-Hub-Signature` with A's `webhook_secret`) can send a `push`/`check_suite`/`status` payload where `repository.owner.login = "A"` (to pass signature verification) but `repository.full_name = "B/some-repo"` for any other organization **B** whose repositories are also managed by the same Shipit instance. Because `Handler#stacks` only consults `full_name`, the forged event is dispatched against organization B's `Stack`, triggering `sync_github` (which advances the deployable-commit range and can enqueue deploys) or check-run refreshes for a repository the sender has no legitimate access to.

### Impact Explanation
This breaks the binding between "organization that authenticated" and "repository that is written," matching the required Critical impact category of **cross-repository writes**: an actor who only controls organization A's webhook secret can inject synthetic push/status/check-suite events that mutate Stack/Commit state for organization B's repositories, potentially triggering continuous-deployment syncs or corrupting CI status history for repositories they do not own or administer.

### Likelihood Explanation
Exploitability requires: (1) the Shipit instance to be configured with multiple GitHub organizations (explicitly supported and documented, see `secrets.development.example.yml` and `docs/setup.md`), and (2) the attacker to hold a legitimate webhook secret for at least one configured organization (e.g., they administer that org's GitHub App installation) but not for the target organization. This is a realistic multi-tenant scenario for shared Shipit deployments and requires no GitHub App private key, no `api_clients_secret`, and no Shipit session — only knowledge of one organization's own webhook secret, which is unprivileged relative to the victim organization.

### Recommendation
In `Handler#repository_name`/`#stacks`, cross-check that the owner segment of `repository.full_name` matches the `repository.owner.login` (or `organization.login`) value that was used to select the verifying `GitHubApp`/secret in `WebhooksController`, rejecting the event (e.g. 422) on mismatch. Alternatively, thread the verified `repository_owner` through to the handlers and have `Repository.from_github_repo_name` enforce that the resolved repository's `owner` equals the authenticated organization before any state mutation occurs.

### Proof of Concept
Conceptual request (illustrative; requires a real HMAC computed with organization A's actual `webhook_secret`):
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<valid HMAC of body using org-A's webhook_secret>

{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "org-A" },
    "full_name": "org-B/victim-repo"
  }
}
```
`verify_signature` resolves `repository_owner` = `"org-A"` and successfully verifies the signature using org A's secret. `PushHandler` then resolves `stacks` via `payload.dig('repository','full_name')` = `"org-B/victim-repo"`, and calls `stack.sync_github` on org B's stack — a repository the sender does not administer and for which they never proved possession of a valid webhook secret.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
