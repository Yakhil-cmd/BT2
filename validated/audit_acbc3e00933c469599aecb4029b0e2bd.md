### Title
Webhook signature verification key selection (`repository_owner`) is never bound to the repository actually mutated by handlers (`repository_name`) - ([File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret using `repository_owner` (`params.dig('repository','owner','login')`), while every `Handler` subclass selects the repository/stack to mutate using `Handler#repository_name` (`payload.dig('repository','full_name')`). Nothing in the controller, `Handler` base class, or any model constraint checks that these two independently-read fields agree, so a single attacker-crafted JSON body can pass signature verification "as org A" while acting on org B's stack.

### Finding Description
Binding claimed by the question, stated as an equality that should hold for every request:
`params.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first`

Trace:
- `WebhooksController#verify_signature` selects the GitHub App/secret with `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature(signature, raw_body)`. [1](#0-0) 
- `repository_owner` is read from the same JSON body the attacker controls: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [2](#0-1) 
- `GitHubApp#verify_webhook_signature` **short-circuits to `true` when no `webhook_secret` is configured** for that organization: `return true unless webhook_secret`. [3](#0-2) 
- A `webhook_secret` is explicitly documented as **optional** per organization, and the test fixtures include a live example (`OrgTwo`) with `webhook_secret: # nil`. [4](#0-3) 
- After signature verification passes, `Handler#repository_name` reads `payload.dig('repository', 'full_name')` — a completely separate field from `repository_owner` — and `#stacks` resolves it via `Repository.from_github_repo_name(repository_name)&.stacks`, with no comparison back to `repository_owner`. [5](#0-4) 
- Every subclass (`PushHandler`, `StatusHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`) resolves its target `Repository`/`Stack` the same way, purely from `params.repository.full_name`, never from `repository_owner`. [6](#0-5) [7](#0-6) 
- `Repository.from_github_repo_name` does an unauthenticated DB lookup keyed purely off the string split of `full_name`. [8](#0-7) 

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: push` (or `pull_request`, `status`, etc.), body `{"repository":{"owner":{"login":"org-with-blank-secret"},"full_name":"victim-org/victim-repo"},"ref":"refs/heads/main","after":"<sha>"}` and any/no `X-Hub-Signature` header. `verify_signature` resolves the GitHub App config for `org-with-blank-secret` (attacker only needs to know/guess the name of *any* Shipit-registered org that happens to have no `webhook_secret` configured — this is a supported, documented configuration, not a stolen secret), gets `webhook_secret` blank, and `verify_webhook_signature` returns `true` unconditionally, regardless of the signature header. The request then flows to `PushHandler#process`, which calls `stacks` on `Handler`, which resolves `victim-org/victim-repo`'s `Stack` records via `full_name` and triggers `stack.sync_github(expected_head_sha: ...)` — a write against a repository/organization the attacker never authenticated as.

Existing guards that were checked and do not prevent this:
- `drop_unhandled_event` only checks the event type is registered, not payload consistency.
- `ExplicitParameters` schemas (`ClosedHandler`, `OpenedHandler`, etc.) validate types/shape of `repository.full_name` but never cross-validate it against `repository.owner.login` or the controller's `repository_owner`.
- `Repository` model validations (`owner`, `name` format/length) validate the stored repository's own fields, not the relationship between the webhook's claimed owner and its claimed full name.
- No `before_action`, no shared helper, no association ties `WebhooksController#repository_owner` to `Handler#repository_name`.

### Impact Explanation
An attacker who knows (or can enumerate/guess) the name of any one Shipit-registered GitHub organization whose `webhook_secret` is unset can forge webhook events that mutate the state of **any other organization's** repositories/stacks tracked by that same Shipit instance: triggering `GithubSyncJob` (push), writing `Status` records against arbitrary commits (`status`), archiving/unarchiving/creating review stacks via labels or PR lifecycle events (`pull_request.*`). This breaks tenant isolation across organizations sharing one Shipit deployment (a documented supported topology — "Using Multiple GitHub Applications") and matches the Critical category "a payload for one repository mutating another's stack, commit, task or team" as well as an authentication-bypass (forged webhook accepted). It is fully repeatable per request and works against any repository/stack present in the datastore, not just ones belonging to the misconfigured org.

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one configured GitHub organization with `webhook_secret` blank/unset (an explicitly documented, optional field with real usage precedent in the codebase's own fixtures) OR be in single-app "backward compatibility" mode with no secret set at all. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body and correct `X-Github-Event` header — no GitHub account, no PR, no push access, no secrets needed. If such a blank-secret org exists, exploitation is trivial and repeatable against every stack in the system. If every configured org has a non-blank secret, the attack is blocked at `verify_webhook_signature`, so likelihood is conditional on this specific (but supported and documented) configuration state.

### Recommendation
Enforce the binding explicitly: in `Handler` (or `WebhooksController#create` before dispatch), verify that `payload.dig('repository','full_name')&.split('/')&.first == repository_owner` (case-insensitively) and reject/drop the event otherwise. Additionally, treat a blank/unset `webhook_secret` as a hard misconfiguration in production (log a loud warning or refuse signature bypass) rather than silently returning `true` in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
minitest plan (extends `test/controllers/webhooks_controller_test.rb` conventions):
```ruby
test "push webhook with divergent owner and full_name mutates unrelated stack" do
  # Arrange: org "org_no_secret" configured with webhook_secret: nil (as in
  # test/dummy/config/secrets_double_github_app.yml OrgTwo), and @stack belongs to
  # repository owner "shopify" (shipit_stacks(:shipit)).
  request.headers['X-Github-Event'] = 'push'
  payload = {
    repository: { owner: { login: 'org_no_secret' }, full_name: @stack.repository.github_repo_name },
    ref: 'refs/heads/master',
    after: 'deadbeef'
  }.to_json

  # Equality being violated:
  owner_used_for_secret = JSON.parse(payload).dig('repository', 'owner', 'login') # "org_no_secret"
  owner_of_mutated_repo = JSON.parse(payload).dig('repository', 'full_name').split('/').first # "shopify"
  refute_equal owner_used_for_secret, owner_of_mutated_repo

  # Act: no valid X-Hub-Signature is set, yet request succeeds because org_no_secret has no webhook_secret.
  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha: 'deadbeef']) do
    post :create, body: payload, as: :json
  end
  assert_response :ok
end
```
This demonstrates that `repository_owner` (signature-selection key) and `repository_name`'s owner segment (mutation target) diverge, and the request still runs a handler that mutates the victim stack — with no code anywhere enforcing the equality.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
