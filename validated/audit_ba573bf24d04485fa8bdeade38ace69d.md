### Title
Cross-tenant webhook confusion: signature verified against `repository.owner.login` but stack resolved from unchecked `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check using `repository_owner` (`payload.dig('repository','owner','login')`), while `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` resolve the target `Repository`/`Stack` using `payload.dig('repository','full_name')`. Both fields are attacker-controlled parts of the same raw JSON body, and no code anywhere checks that the owner segment of `full_name` equals `repository.owner.login`.

### Finding Description
The broken binding: `repository.owner.login` (used at `verify_signature` time to pick the GitHub App/secret) is never checked for equality against the owner segment of `repository.full_name` (used at `Handler#repository_name`/`#stacks` time to resolve the target tenant).

Code path:
- `WebhooksController#verify_signature` computes `repository_owner` from the request body [1](#0-0) , and uses it to fetch the org-specific `GitHubApp` and check the signature with that org's `webhook_secret` [2](#0-1) .
- `WebhooksController#create` re-parses the identical raw body and dispatches it, unmodified, to the event handlers [3](#0-2) .
- `Handler#stacks` resolves the target `Repository` purely from `payload.dig('repository','full_name')` via `Repository.from_github_repo_name`, with no reference to `owner.login` [4](#0-3) .
- `Repository.from_github_repo_name` just splits the string on `/` and does a `find_by` — it performs no cross-check against any authenticated owner [5](#0-4) .
- `PushHandler#process` then loads matching stacks for that branch and calls `stack.sync_github`, i.e. it acts on whatever repository `full_name` says, not whatever org the signature says [6](#0-5) .

Root cause: Shipit's multi-tenant GitHub App configuration (`docs/setup.md`, "Using Multiple Github Applications") maps organization name → GitHub App credentials/`webhook_secret` [7](#0-6) , and this mapping is looked up via `Shipit.github(organization: repository_owner)` purely from client-supplied JSON, with the implicit (but code-unenforced) assumption that whichever org's secret validates the signature also owns the `repository.full_name` in that same payload. GitHub itself enforces this coupling naturally (an app installed on org A only ever emits payloads about org A's repos), but this engine performs no equivalent server-side check.

Attacker's exact request: an attacker who administers GitHub org `attacker-org` (and thus knows or controls the webhook_secret configured for `attacker-org` in Shipit's per-org secrets) crafts an arbitrary HTTP POST to `/webhooks` with header `X-Github-Event: push` and a body such as:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": {"login": "attacker-org"},
    "full_name": "victim-org/victim-repo"
  }
}
```
signed with `X-Hub-Signature: sha1=<HMAC using attacker-org's webhook_secret over this exact body>`. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')` and the signature matches, so the request passes. `create` then dispatches the same payload to `PushHandler`, which resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and enqueues `stack.sync_github` for `victim-org`'s stack — a job triggered under `attacker-org`'s own valid signature but acting on a different tenant's repository/stack.

None of the existing guards catch this: `verify_signature` only checks HMAC validity for whichever org name is embedded in the payload, `drop_unhandled_event` only filters by event type, `ExplicitParameters` schemas (e.g., in `PushHandler`) only validate the shape/presence of fields, not cross-field consistency, and `Repository.from_github_repo_name`/model validations only constrain the format of `owner`/`name`, not that they match the webhook's authenticated identity.

### Impact Explanation
An attacker with legitimate control of one tenant org (`attacker-org`) configured in Shipit's multi-org GitHub App setup can forge push/status/check_suite/pull_request-style webhook payloads that claim to be about a completely different tenant's repository (`victim-org/victim-repo`), causing Shipit to enqueue `GithubSyncJob`, update commit statuses, refresh check runs, or (via pull_request handlers) archive/unarchive/provision review stacks for that unrelated repository/stack — all under the attacker's own valid signature. This is a payload for one repository mutating another's stack/commit, matching the Critical impact category. It is fully repeatable against any repository whose `owner/name` the attacker can guess or discover, and the blast radius spans every tenant org configured in the same Shipit instance.

### Likelihood Explanation
This requires the Shipit instance to be configured for multiple GitHub organizations (the per-org `github:` config block), and requires the attacker to already control one legitimate tenant org with a known `webhook_secret` for that org (a precondition the question itself grants as a given: "attacker who controls org ORG_A with a valid webhook_secret"). Given that, the attack cost is trivial — a single crafted HTTP POST with a correctly computed HMAC — and is fully repeatable and scriptable against arbitrary target repository names known to the attacker.

### Recommendation
In `WebhooksController` (or `Handler`), after signature verification, enforce that the resolved `repository_owner` used for signature verification equals the owner segment of `repository.full_name` (or `organization.login`) before dispatching to handlers; reject the request (422) on mismatch. Equivalently, have `Repository.from_github_repo_name` calls in handlers cross-check the payload's authenticated owner against the repository's stored owner before acting.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`):
1. Configure `Shipit.secrets.github` with two orgs, `attacker-org` (webhook_secret `secret_a`) and `victim-org` (webhook_secret `secret_b`), matching the multi-org schema in `lib/shipit.rb`.
2. Create a `Shipit::Stack`/`Repository` fixture for `victim-org/victim-repo`.
3. Build a push payload: `{"ref"=>"refs/heads/master","after"=>"deadbeef","repository"=>{"owner"=>{"login"=>"attacker-org"},"full_name"=>"victim-org/victim-repo"}}`.
4. Compute `signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'secret_a', payload.to_json)`.
5. POST to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature: signature`.
6. Assert both sides of the binding: `repository_owner` (= `'attacker-org'`) used for signature selection is NOT equal to `repository.full_name.split('/').first` (= `'victim-org'`), yet:
   - `assert_response :ok` (request accepted, signature validated against attacker-org's secret).
   - `assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: 'deadbeef'])` — proving `victim-org`'s stack was synced by a payload authenticated only against `attacker-org`'s secret.

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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
