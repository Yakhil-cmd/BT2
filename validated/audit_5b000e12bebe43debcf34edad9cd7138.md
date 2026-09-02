### Title
Repository owner used only to pick the webhook secret for verification, while the actual affected repository/stack comes from an unvalidated `repository.full_name` field - allows cross-tenant forged `pull_request` `closed` events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` config (and thus which `webhook_secret`) to use for HMAC verification based on `params.dig('repository','owner','login')` only. `ClosedHandler` (and the other PR handlers), by contrast, resolve the affected `Repository`/`ReviewStack` from an entirely separate field, `params.repository.full_name`. Nothing in the request enforces that these two attacker-supplied strings agree, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org's config has no `webhook_secret` configured.

### Finding Description
The broken binding: the code implicitly assumes `repository.owner.login == full_name.split('/').first` for the same repository, i.e. it assumes "the org whose secret verified this request" equals "the org whose stack is mutated by this request." That equality is never checked.

- `verify_signature` in [1](#0-0)  computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (`repository_owner` defined at [2](#0-1) ) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`.
- `GitHubApp#verify_webhook_signature` returns `true` immediately if the resolved org's `@webhook_secret` is blank: [3](#0-2) .
- `ClosedHandler#repository` resolves the affected repository from `params.repository.full_name`, a completely different payload field: [4](#0-3) , and then archives the matching `ReviewStack`: [5](#0-4) .

Exploit flow: attacker crafts a JSON body with `repository.owner.login = "no-secret-org"` (an org configured in Shipit's secrets but whose config entry has no `webhook_secret`) and `repository.full_name = "victim-org/victim-repo"` (the real target, whose config does have a secret). `verify_signature` looks up `Shipit.github(organization: "no-secret-org")`, which returns a `GitHubApp` with `webhook_secret` blank, so `verify_webhook_signature` returns `true` with no HMAC check at all — the request is accepted regardless of the `X-Hub-Signature` header. `ClosedHandler` then runs against `victim-org/victim-repo`'s `ReviewStack`, archiving it based purely on `params.repository.full_name` and `params.number`, i.e., a payload that was never authenticated by victim-org's own secret.

This is a genuine repository-confusion bug matching the "no-secret organization" gap described in the question: verification and mutation key off two different, independently attacker-controlled fields.

### Impact Explanation
An attacker who knows (a) that some org configured in Shipit lacks a `webhook_secret`, and (b) the `owner/name` of a victim repo with review stacks enabled, can forge a `pull_request` `closed` event and have it accepted without any valid signature, then have it archive the victim's `ReviewStack` for an arbitrary PR number. This is a cross-tenant "payload for one repository mutating another's stack" scenario. `ClosedHandler` itself only calls `review_stack.archive!` — it does not itself trigger a deploy/rollback. The "bot_login configured (Shipit.user)" detail in the question concerns `Shipit.user`, used elsewhere (e.g. as the actor for auto-merges/some background operations, `lib/shipit.rb:208-214`), but `ClosedHandler` does not invoke any deploy pipeline as part of archiving — I did not find code in `ClosedHandler` or `ReviewStackAdapter`/`archive!` that triggers a bot-run deploy as a direct consequence of this handler. The concretely demonstrable impact of this specific gap is: unauthenticated archival of an arbitrary victim `ReviewStack`, i.e., an unauthorized state-changing write against a repository that did not authenticate the request — a real but narrower impact than "unauthorized deploy" as stated in the prompt, since I could not trace `archive!` to a bot-run deploy trigger within the code inspected.

### Likelihood Explanation
Preconditions: (1) at least one org configured under `Shipit`'s multi-org GitHub config with a missing/blank `webhook_secret`; (2) a victim repository with review stacks enabled elsewhere in the same Shipit instance. Both are plausible misconfigurations but are configuration-dependent (not universal defaults) — the codebase does support and does not forbid an org config without `webhook_secret` (`@webhook_secret = @config[:webhook_secret].presence`, `github_app.rb:50`). The attack costs a single crafted HTTP POST with no secrets, fully repeatable and scriptable against any PR number/review stack once the no-secret org is identified.

### Recommendation
Bind signature verification to the same repository identity used by the handlers: derive the org from `params.repository.full_name` (not from `repository.owner.login`), and additionally validate that `repository.owner.login` (when present) matches the owner segment of `full_name` before dispatching to handlers. Also consider rejecting/erroring when a configured org has a blank `webhook_secret` rather than silently allowing unsigned traffic.

### Proof of Concept
```ruby
test "cross-org forged pull_request closed event using a no-secret organization archives victim review stack" do
  # Setup: org "no-secret-org" configured with no webhook_secret; victim repo "victim-org/victim-repo"
  # with review stacks enabled and an open ReviewStack for PR #42.
  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid signature

  body = {
    action: 'closed',
    number: 42,
    pull_request: {
      id: 1, number: 42, url: 'https://api.github.com/...', title: 't', state: 'closed',
      additions: 1, deletions: 1,
      head: { sha: 'abc', ref: 'branch' },
      user: { login: 'attacker' }, assignees: [], labels: []
    },
    repository: {
      full_name: 'victim-org/victim-repo',   # actual target
      owner: { login: 'no-secret-org' }      # used only for signature bypass
    },
    sender: { login: 'attacker' }
  }.to_json

  review_stack = shipit_review_stacks(:victim_open_stack) # bound to victim-org/victim-repo #42

  assert_not review_stack.archived?

  post :create, body: body, as: :json

  assert_response :ok
  assert review_stack.reload.archived?, "victim ReviewStack archived by a payload not authenticated by victim-org's secret"
end
```
Assert both sides of the binding: before the request, `repository_owner` ("no-secret-org") ≠ `params.repository.full_name`'s owner ("victim-org"), yet the request is accepted (`assert_response :ok`) and mutates `victim-org/victim-repo`'s state — proving the equality the code implicitly assumes does not hold and is not checked.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
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
