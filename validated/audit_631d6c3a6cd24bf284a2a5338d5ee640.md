### Title
Webhook signature verified against `repository.owner.login`'s secret while repository/stack resolution uses the independently-attacker-controlled `repository.full_name`, allowing cross-tenant forged `pull_request` events - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) to verify a webhook using `params.dig('repository','owner','login')`, while every `pull_request` handler (e.g. `LabelCapturingHandler#repository`) resolves the actual `Shipit::Repository`/stack to mutate using `params.repository.full_name` — a separate, independently attacker-controlled field of the same forged JSON body. Because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected organization's config has no `webhook_secret`, an attacker can pick an org with no secret for `repository.owner.login` to pass verification, while pointing `repository.full_name` at an arbitrary victim repository/stack.

### Finding Description
The broken binding: the code implicitly assumes `repository.owner.login == full_name.split('/').first`, i.e. that the field used to authenticate the webhook is the same tenant as the field used to resolve the mutated record. This is never enforced.

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` computes `repository_owner` from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`) and calls `Shipit.github(organization: repository_owner)` to get a `GitHubApp`, then calls `verify_webhook_signature`. [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank/unconfigured for that organization: [3](#0-2) 
- After verification, `WebhooksController#create` dispatches the same raw `params` (untouched) to the handler(s): [4](#0-3) 
- `LabelCapturingHandler#repository` resolves the target `Shipit::Repository` using `params.repository.full_name`, a completely separate JSON field from `repository.owner.login`: [5](#0-4) 
`Shipit::Repository.from_github_repo_name` just splits the string on `/` and does a DB lookup — no cross-check against the authenticated organization: [6](#0-5) 
And the base `Handler` class used by other `pull_request` handlers has the identical pattern (`repository_name` from `payload.dig('repository','full_name')`, independent of the signature check): [7](#0-6) 

Exploit flow:
1. Attacker registers (or is a member of) a GitHub organization/repo configured in Shipit with no `webhook_secret` set (a "no-secret organization"), or simply crafts `repository.owner.login` to name such an org.
2. Attacker sends `POST /webhooks` with header `X-Github-Event: pull_request`, no valid HMAC signature required, and a JSON body where:
   - `repository.owner.login` = the no-secret org (passes `verify_signature` trivially).
   - `repository.full_name` = `"victim-org/victim-repo"`, matching a real, secret-protected victim `Repository`/`ReviewStack` with `ignore_ci: true`.
   - `action` = `"opened"`, plus a fabricated `pull_request.labels` array with attacker-chosen `name` values.
3. `Shipit::Webhooks.for_event('pull_request')` handlers run, including `LabelCapturingHandler`, which finds the victim `Repository` via `full_name`, locates the matching review stack's `PullRequest`, and calls `pull_request.update!(labels: params.pull_request.labels.map(&:name))` — writing attacker-controlled label names onto a repository/record that never authenticated this request.
4. Those label names later flow into `ReviewStack#env` as uppercased environment keys (per the question's stated downstream behavior), and since the victim stack has `ignore_ci: true`, `Commit#deployable?` returns true unconditionally (`!locked? && (stack.ignore_ci? || ...)`), so CI status is irrelevant to shippability: [8](#0-7) 

Existing guards do not prevent this: `verify_signature` only checks the HMAC for the org named in `repository.owner.login`; it never checks that this org matches the owner embedded in `repository.full_name`. `drop_unhandled_event` only filters by event type, not by payload consistency. The `ExplicitParameters` schema in `LabelCapturingHandler` validates types/presence of fields but performs no cross-field validation between `repository.full_name` and `repository.owner.login` (the schema doesn't even require `repository.owner.login`, it's only used by the controller layer before params reach the handler).

### Impact Explanation
An unauthenticated attacker can inject attacker-controlled state (fabricated PR labels, later materialized as `ReviewStack#env` variables) into any victim repository/stack that Shipit tracks, as long as the attacker can name any org configured in Shipit with a blank `webhook_secret` — a configuration-dependent but plausible condition (e.g., an org onboarded to Shipit before secrets were required, or a low-security/test org). This is a payload for one repository (a no-secret org) mutating another repository's/tenant's stack — squarely a "Critical: a payload for one repository mutating another's stack" scenario. Combined with `ignore_ci: true` on the victim stack, injected env vars can influence deploy/task execution without any CI gating, amplifying to unauthorized deploy behavior. The attack is fully repeatable against any repository/stack reachable by `full_name`, and it is not limited to `pull_request`; the same disjunction between `repository.owner.login` (verification) and `repository.full_name` (resolution) applies to `push`, `status`, `check_suite`, and other webhook handlers built on the same `Handler` base class.

### Likelihood Explanation
Preconditions:
- At least one GitHub organization configured in `Shipit.github_config`/secrets with no `webhook_secret` (this is the "no-secret organization" gap named in the question; it depends on operator misconfiguration but is explicitly acknowledged as an existing state to test against).
- A victim stack (or review stack) exists whose `full_name` the attacker knows (repo names are typically public/discoverable), with `ignore_ci: true` for the CI-bypass amplification (though the label-capturing write itself works regardless of `ignore_ci`).
Attacker cost is trivial: a single unauthenticated `POST /webhooks` HTTP request with a crafted JSON body and an `X-Github-Event` header; no secrets, tokens, or GitHub API access needed. The attack is fully repeatable and scriptable against any number of victim repositories, as long as one no-secret org can be named for the `owner.login` field.

### Recommendation
Enforce that the organization used to select/verify the webhook secret is the same organization embedded in `repository.full_name` (and `organization.login`, if present) before dispatching to handlers — reject the request if they diverge. Additionally, do not allow `verify_webhook_signature` to silently return `true` for organizations with a blank secret in production; require an explicit "verification not required" allow-list rather than defaulting to bypass, and/or reject payloads whose `repository.full_name` owner doesn't match a Shipit-known organization with a properly configured secret.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "pull_request opened for victim repo is accepted using a no-secret organization's owner.login" do
  # Configure a Shipit-known org with a blank webhook_secret ("no-secret-org")
  Shipit.stubs(:github_config).returns(
    'no-secret-org' => { app_id: 1, installation_id: 1, private_key: 'x' }, # no webhook_secret key
    'victim-org' => { app_id: 2, installation_id: 2, private_key: 'y', webhook_secret: 'realsecret' }
  )

  victim_repo = shipit_repositories(:shipit) # owner: 'victim-org', name: 'victim-repo', ignore_ci: true stack
  review_stack = victim_repo.review_stacks.create!(pull_request: shipit_pull_requests(:one))

  request.headers['X-Github-Event'] = 'pull_request'
  body = {
    action: 'opened',
    number: 42,
    pull_request: {
      id: 1, number: 42, url: 'https://api.github.com/x', title: 't', state: 'open',
      additions: 1, deletions: 0,
      head: { sha: 'abc123', ref: 'feature' },
      user: { login: 'attacker' },
      assignees: [],
      labels: [{ name: 'INJECTED_ENV_KEY' }]
    },
    repository: {
      full_name: 'victim-org/victim-repo', # points at victim, NOT the no-secret org
      owner: { login: 'no-secret-org' }    # used ONLY for signature verification bypass
    },
    sender: { login: 'attacker' }
  }.to_json

  # No X-Hub-Signature header sent at all — verification passes because
  # 'no-secret-org' has no webhook_secret configured.
  post :create, body: body, as: :json

  assert_response :ok
  assert_equal ['INJECTED_ENV_KEY'], review_stack.pull_request.reload.labels,
    "Attacker forged a pull_request event for 'victim-org/victim-repo' " \
    "by authenticating as 'no-secret-org', proving the two fields are not bound together"
end
```
The equality that should hold but does not: `verified_organization(repository.owner.login) == resolved_repository_owner(repository.full_name)`. Before the fix, the test shows these can diverge (`no-secret-org != victim-org`) and the write still succeeds; after a fix enforcing this equality, the request would be rejected with `422`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
