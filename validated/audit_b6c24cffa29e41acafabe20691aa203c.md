### Title
`pull_request` webhook verified against `repository.owner.login`'s org but mutates the repo resolved from `repository.full_name`, allowing cross-org state injection when the verifying org has no `webhook_secret` — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the signing key using `repository.owner.login`, while every `pull_request` handler (including `LabelCapturingHandler`) resolves the actual `Repository`/`Stack` to mutate using `repository.full_name`. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has no configured `webhook_secret`. An attacker who controls (or names) an org with no `webhook_secret` in `repository.owner.login` can set `repository.full_name` to any other org's real `owner/repo`, pass verification for free, and have the handler write to that victim repository's `PullRequest`/`ReviewStack`.

### Finding Description
The broken binding, stated as an equality that must hold but doesn't:
`org_used_to_verify_signature (params.dig('repository','owner','login'))` == `org_that_owns_the_mutated_repository (params.repository.full_name.split('/').first)`

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` strictly from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and fetches `Shipit.github(organization: repository_owner)`: [1](#0-0) [2](#0-1) 
2. `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever no `webhook_secret` is configured for that org: [3](#0-2) 
3. If verification passes (or the org is genuinely secret-less), `WebhooksController#create` dispatches the *entire raw payload* to all registered handlers for the event, without re-checking which org/repo it belongs to: [4](#0-3) 
4. `LabelCapturingHandler#repository` resolves the target `Repository` from a completely different field, `params.repository.full_name`, not from `repository.owner.login`: [5](#0-4) 
5. `Repository.from_github_repo_name` splits `full_name` on `/` and looks the record up purely by `owner`/`name` strings, with no cross-check against `repository.owner.login` or the org used for signature verification: [6](#0-5) 
6. `LabelCapturingHandler#capture_labels` then persists attacker-supplied label names onto the resolved (victim) stack's `PullRequest`: [7](#0-6) 

Exploit: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request`, body `action: "opened"`, `repository.owner.login = "attacker-controlled-org-with-no-webhook_secret"`, `repository.full_name = "victim-org/victim-repo"` (a real repo/stack with `blocking_statuses` configured), and `pull_request.labels` set to whatever names the attacker wants persisted. `verify_signature` resolves `Shipit.github(organization: "attacker-controlled-org...")`, finds no `webhook_secret` for it, and returns `true` regardless of the actual `X-Hub-Signature` header content. The request is accepted and dispatched. `LabelCapturingHandler` then resolves `repository` from `full_name` = `victim-org/victim-repo`, finds the real `Stack`'s `PullRequest`, and overwrites its `labels` with attacker-chosen values — which the question states become uppercased environment keys via `ReviewStack#env`, capable of toggling forced-status-driven `blocked?` gating on a stack the attacker never authenticated against.

Existing guards do not prevent this: `verify_signature` never compares `repository.owner.login` against `repository.full_name`'s owner segment; `drop_unhandled_event` only checks event type, not payload consistency; the `ExplicitParameters` schema (`params do ... end` block in `LabelCapturingHandler`) validates types/presence but not that `full_name`'s owner matches `repository.owner.login`; there is no `require_permission!`, session, or API-client check on this unauthenticated endpoint by design (it is meant to be driven by GitHub's HMAC signature alone).

### Impact Explanation
A payload nominally "from" one (no-secret) organization mutates a `PullRequest`/`Stack` belonging to a completely different, real organization that the attacker does not control and never authenticated against — this is exactly the Critical category "a payload for one repository mutating another's stack, commit, task or team." The forced label values become environment variables via `ReviewStack#env` and can influence `blocked?`/deploy gating on `blocking_statuses`-configured stacks, i.e., unauthorized manipulation of deploy gating state. This is repeatable against any repository/stack whose `owner/name` the attacker can guess or discover, as long as one org anywhere in the Shipit config lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: (a) at least one org configured in Shipit's GitHub app config with no `webhook_secret` set (or the attacker can get `Shipit.github` to resolve such a no-secret config for an org name they choose), and (b) a victim `Stack`/`ReviewStack` exists for the targeted `owner/repo` with `blocking_statuses` configured. Attacker cost is a single crafted HTTP POST with no valid GitHub signature knowledge required, fully repeatable, and requires no privileges, session, or token — matching the "unprivileged attacker" threat model in the prompt.

### Recommendation
In `WebhooksController#verify_signature`, require that `repository.owner.login` (or `organization.login`) matches the owner segment of `repository.full_name` before dispatching, and reject the request otherwise. Additionally, do not allow `verify_webhook_signature` to succeed silently for orgs with no configured secret when the payload targets a resource under a different owner; treat a missing `webhook_secret` as a hard rejection for `pull_request` events that reference `repository.full_name`, or require signature verification to be keyed off `repository.full_name`'s owner rather than the separate `repository.owner.login` field.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` style, illustrative — must be added under `test/`):
```ruby
test "pull_request payload with mismatched owner/full_name mutates a different org's stack" do
  victim_stack = shipit_stacks(:shipit) # owner: "shopify", configured with blocking_statuses
  pr = victim_stack.pull_requests.create!(number: 42, ...)

  # attacker-controlled org with NO webhook_secret configured
  Shipit.stubs(:github).with(organization: "attacker-org").returns(
    Shipit::GitHubApp.new("attacker-org", {}) # no webhook_secret key
  )

  payload = {
    action: "opened",
    number: 42,
    pull_request: { id: 1, number: 42, url: "...", title: "x", state: "open",
      additions: 1, deletions: 0, head: { sha: "a"*40, ref: "attacker-branch" },
      user: { login: "attacker" }, assignees: [],
      labels: [{ name: "FORCED_UNBLOCK" }] },
    repository: { owner: { login: "attacker-org" }, full_name: "shopify/shipit-engine" }, # victim repo!
    sender: { login: "attacker" }
  }.to_json

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary / invalid

  assert_equal "attacker-org", JSON.parse(payload).dig("repository","owner","login")
  assert_equal "shopify", JSON.parse(payload).dig("repository","full_name").split("/").first
  # binding under test: these two must be equal for verification to be meaningful; they are NOT

  post :create, body: payload, as: :json
  assert_response :ok

  pr.reload
  assert_equal ["FORCED_UNBLOCK"], pr.labels
  # victim_stack's env/blocked? state derived from labels has been altered by a payload
  # that was verified using "attacker-org"'s (secret-less) key, not shopify's.
end
```
This demonstrates the equality `repository_owner used for verify_signature` != `owner of repository.full_name mutated by the handler`, and shows the resulting write lands on the victim's `PullRequest` record.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
