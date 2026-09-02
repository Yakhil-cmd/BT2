### Title
Webhook signature is verified against an attacker-chosen `repository.owner.login`, letting a payload's `repository.full_name` target an unrelated stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App config (and thus which `webhook_secret`) to verify the request against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')`). Every `pull_request` handler (including `LabelCapturingHandler`, `UnlabeledHandler`, etc.) instead resolves the actual target `Repository`/`Stack` using a *different* field of the same untrusted body, `params.repository.full_name`. Because nothing enforces that these two fields refer to the same repository, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the resolved org has no `webhook_secret` configured (webhook secret is documented as *optional*, docs/setup.md:30/119), an attacker can pick any Shipit-configured organization that has no secret set, put its login in `repository.owner.login`, and put an arbitrary victim `owner/repo` in `repository.full_name` to have the forged event applied to the victim stack with no valid signature at all.

### Finding Description
The broken binding the code implicitly assumes is:
`params.dig('repository','owner','login') == owner_segment_of(params.repository.full_name)`

Nothing in the code enforces this equality, so it does not hold for an attacker-crafted payload.

Trace:
1. `Shipit::WebhooksController#verify_signature` [1](#0-0)  computes `repository_owner` from `params.dig('repository', 'owner', 'login')` [2](#0-1)  and calls `Shipit.github(organization: repository_owner)` to pick a `GitHubApp` instance, then `verify_webhook_signature`.
2. `Shipit.github` looks up per-organization config via `github_app_config(organization)` in multi-org mode [3](#0-2) .
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's `webhook_secret` is blank: `return true unless webhook_secret` [4](#0-3) . The setup docs mark `webhook_secret` as optional per org [5](#0-4) , and multi-org installs configure one App block per org independently [6](#0-5) .
4. Once `verify_signature` passes (either genuinely, or trivially because the chosen org has no secret), `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers against the raw JSON `params` [7](#0-6) .
5. `LabelCapturingHandler` (and every other `pull_request` handler) resolves the acted-upon repository from a *separate* field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name` [8](#0-7) , then finds the review `Stack` by `environment` under that repository's `review_stacks` scope [9](#0-8) , and persists attacker-supplied label names onto that stack's `PullRequest` [10](#0-9) .

Exploit request: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, no valid `X-Hub-Signature` (or any garbage signature — it doesn't matter), and a body such as:
```json
{
  "action": "unlabeled",
  "number": 42,
  "repository": {
    "owner": { "login": "org-with-no-webhook-secret" },
    "full_name": "victim-org/victim-repo"
  },
  "pull_request": { ... victim PR fields, attacker-chosen labels ... },
  "sender": { "login": "attacker" }
}
```
`repository_owner` resolves to `"org-with-no-webhook-secret"`, which is a real org configured in the same Shipit instance (satisfying the `GithubOrganizationUnknown` guard so the request isn't rejected with 422), but that org's config has no `webhook_secret` set, so `verify_webhook_signature` returns `true` regardless of the signature header. The handler then acts on `victim-org/victim-repo`'s stack because that's what `params.repository.full_name` says, not `org-with-no-webhook-secret`.

Existing guards that fail to stop this:
- `drop_unhandled_event` only checks the event name is registered, not the payload's internal consistency.
- `verify_signature`'s only cross-check is `GithubOrganizationUnknown`, which merely confirms `repository_owner` names *some* configured org — it does not confirm that org owns the repository named in `repository.full_name`.
- `ExplicitParameters` schemas on the handlers (`requires :repository { requires :full_name, String }`) only type-check the field; they never compare it against `repository.owner.login`.
- `Repository.from_github_repo_name` and `review_stacks` scoping correctly isolate stacks *by full_name*, but that's precisely the field the attacker controls independently of the field used for authentication.

### Impact Explanation
Any org configured in the same multi-tenant Shipit instance without a `webhook_secret` becomes a skeleton key for every other org/repo/stack the instance manages. An attacker can forge `pull_request` events (opened/labeled/unlabeled/reopened/closed) for a victim repository's review stack with `merge_queue_enabled: true`, mutate `PullRequest#labels` via `LabelCapturingHandler`, and those labels flow into `ReviewStack#env` as uppercased environment variables consumed during provisioning/deploy commands. Combined with the merge queue's `ProcessMergeRequestsJob` calling `MergeRequest#merge!` [11](#0-10)  once a head is green, unauthorized state changes and merges on a repository the attacker never authenticated against are possible — matching the Critical category "a payload for one repository mutating another's stack" and "unauthorized deploy/rollback/merge."

The blast radius is bounded to Shipit installations running the *multi-organization* GitHub App configuration (`docs/setup.md`'s "Using Multiple Github Applications" section) where at least one configured org has no `webhook_secret`. It is fully repeatable — every request against that no-secret org's name can carry an arbitrary `full_name` for any other stack managed by the instance.

### Likelihood Explanation
Preconditions: the Shipit instance must (a) use the multi-org `github:` config format, and (b) have at least one org entry with `webhook_secret` unset/blank — a configuration explicitly permitted since the docs mark it "optional." Attacker cost is a single unauthenticated HTTP POST with no secret material required. This is not exotic: the whole point of the sha1-only acceptance and the "return true unless webhook_secret" branch is legacy/opt-out support, so the misconfiguration is plausible in real deployments that haven't set a secret for every org. Given the precondition, the exploit is trivial and fully repeatable.

### Recommendation
- Make `webhook_secret` mandatory for every configured org (fail closed instead of `return true unless webhook_secret`).
- Cross-validate `repository.owner.login` (used to select the verifying GitHub App/secret) against the owner segment of `repository.full_name` (used to resolve the target `Stack`) before running any handler, rejecting the request if they diverge.
- Prefer deriving the verifying organization from the *stack's own* configured repository/owner rather than from an unauthenticated field of the same payload.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "pull_request unlabeled forged with mismatched owner bypasses signature for a merge_queue_enabled stack" do
  # Precondition: multi-org config where "no-secret-org" has no webhook_secret
  Shipit.stubs(:github).with(organization: "no-secret-org").returns(
    Shipit::GitHubApp.new("no-secret-org", { app_id: 1, installation_id: 1 }) # no webhook_secret
  )

  victim_stack = shipit_stacks(:review_stack) # merge_queue_enabled: true, belongs to victim-org/victim-repo
  pr = victim_stack.create_pull_request! # existing PullRequest with labels: []

  forged_payload = {
    action: "unlabeled",
    number: victim_stack.environment.delete_prefix("pr").to_i,
    repository: {
      owner: { login: "no-secret-org" },       # picks the org with NO webhook_secret
      full_name: victim_stack.github_repo_name # but targets the victim's actual repo/stack
    },
    pull_request: {
      id: 1, number: 1, url: "https://api.github.com/x", title: "x", state: "open",
      additions: 1, deletions: 0,
      head: { sha: "deadbeef", ref: victim_stack.branch },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "ATTACKER_INJECTED" }]
    },
    sender: { login: "attacker" }
  }.to_json

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = "sha1=0000000000000000000000000000000000000000" # invalid/no valid secret

  post :create, body: forged_payload, as: :json

  assert_response :ok # not 422 -> signature check was bypassed via "no-secret-org"
  assert_equal ["ATTACKER_INJECTED"], pr.reload.labels
  # binding check: repository_owner ("no-secret-org") != owner segment of full_name (victim-org)
  refute_equal "no-secret-org", victim_stack.github_repo_name.split("/").first
end
```
This demonstrates the divergence: the value used to authenticate (`repository.owner.login`) is not the value used to authorize the mutation (`repository.full_name`), and a request that should be rejected (`422`) for the victim stack instead succeeds and mutates it.

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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```
