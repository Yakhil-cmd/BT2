### Title
`UnlabeledHandler` resolves the target stack from `params.repository.full_name` with no check against the org whose secret verified the webhook, enabling cross-tenant forced archive - ([File: app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb])

### Summary
`UnlabeledHandler#repository`/`#stack` look up the target `Repository`/`Stack` exclusively via `params.repository.full_name` [1](#0-0) , while `WebhooksController#verify_signature` selects the HMAC secret to validate the request using a completely different, independently-controlled JSON field: `params.dig('repository', 'owner', 'login')` (or `organization.login`) [2](#0-1) . Nothing in the request schema or handler ties these two fields together, so `full_name` and `owner.login` can diverge in the same POST body.

### Finding Description
The binding the question is checking is: `owner_login_used_for_signature == owner_segment_of(params.repository.full_name)`. Tracing the code:

- `WebhooksController#verify_signature` computes `repository_owner` from raw JSON (`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`) and fetches `Shipit.github(organization: repository_owner)` to get that org's `webhook_secret`, then calls `verify_webhook_signature(signature, raw_post)` [3](#0-2) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is not configured for that org (`return true unless webhook_secret`) [4](#0-3) .
- `UnlabeledHandler`'s `params` schema only requires `repository.full_name`; it never requires or reads `repository.owner.login` [5](#0-4) . The handler resolves the `Repository`/`Stack` purely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` [6](#0-5) , then archives/unarchives that stack based on label state also taken directly from the same attacker-supplied JSON body [7](#0-6) .

Because `repository.owner.login` (used to select the verifying org/secret) and `repository.full_name` (used to select the target `Repository`/`Stack`) are two separate fields in the same raw JSON payload with no cross-check, a request whose `repository.owner.login` names org A but whose `repository.full_name` names `"orgB/some-repo"` will be verified using org A's config, yet mutate org B's stack. This precisely mirrors `LabeledHandler`, which has the identical structure (`repository` derived only from `full_name`, no `owner.login` requirement) [8](#0-7) .

Exploitability is gated on being able to pass `verify_signature` for *some* org while naming a different org's repo in `full_name`. This is possible whenever that org's `webhook_secret` is blank/unset in Shipit's config for the org named by `owner.login`/`organization.login` — `verify_webhook_signature` then accepts *any* signature value [9](#0-8) . Under the stated attacker model (arbitrary POST to `/webhooks`, no secrets), the attacker sends a raw POST with `X-Github-Event: pull_request`, body `{"action":"unlabeled","repository":{"full_name":"orgB/target-repo","owner":{"login":"orgWithNoSecret"}},"pull_request":{...,"labels":[]},...}`. `repository_owner` resolves to `"orgWithNoSecret"`, `verify_webhook_signature` returns `true` (no secret configured), `drop_unhandled_event` and `ExplicitParameters` schema checks pass, and `UnlabeledHandler` archives org B's active review stack (`stack.archive!`) purely because `provisioning_behavior_allow_with_label?` and the label is absent from the attacker-chosen `labels: []`.

None of the listed guards prevent this: `drop_unhandled_event` only checks the event type exists as a handler; the `ExplicitParameters` schema only validates types/presence, not cross-field consistency; there is no `require_permission!`/`current_user` check anywhere in this webhook path (webhooks are inherently unauthenticated by user, authenticated only by HMAC); model validations on `Repository`/`Stack` don't validate that the org owning the repo matches any request-time "verifying org" concept — that concept doesn't exist as a first-class value anywhere past the controller.

### Impact Explanation
A successfully forged/mismatched request causes `Shipit::Stack#archive!` (or `unarchive!`) to run against a `Stack` belonging to a different, unrelated repository/org than the one whose secret was used to authorize the request — an unauthorized cross-tenant state mutation on an active review stack, matching the "payload for one repository mutating another's stack" Critical impact category. This is repeatable against any org whose `webhook_secret` is blank in the deployed Shipit config, for any repo/stack known to the attacker (they only need to guess/know `full_name`, e.g. `"victim-org/victim-repo"`), and works identically for `LabeledHandler`.

### Likelihood Explanation
Exploitation strictly requires at least one organization configured in this Shipit instance with no `webhook_secret` set (or an equivalent org resolvable via `organization.login` fallback with no secret) — this is a deployment/configuration precondition, not something guaranteed by the code. Given that in a well-configured, documented deployment every registered GitHub App/organization is expected to have `webhook_secret` set, this is conditional rather than universally exploitable; however, the code contains no defense against it even for correctly configured orgs beyond the assumption that the secret is always non-blank. If any org is misconfigured (blank secret) — plausible for self-hosted/multi-tenant instances with many orgs — the attack is a single unauthenticated HTTP POST, fully repeatable.

### Recommendation
Bind the resolved `Repository`/`Stack`'s owner to the org that verified the signature: require and validate `repository.owner.login` in the `ExplicitParameters` schema for all pull_request handlers, and reject the request (or refuse to resolve `full_name` against a different repo) unless `repository.owner.login`/`organization.login` used for `verify_signature` matches the owner segment of `repository.full_name`. Additionally, stop treating a missing `webhook_secret` as automatically valid in `GitHubApp#verify_webhook_signature`; require an explicit opt-out flag instead of silently accepting unsigned requests.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition, no live GitHub)
test "unlabeled webhook cannot archive a stack belonging to a different org than the one that verified it" do
  org_a = "org-with-no-secret"       # Shipit.github(organization: org_a).webhook_secret is blank
  org_b_repo = shipit_repositories(:review_stack_repo) # owned by a different org, review_stacks_enabled
  org_b_stack = shipit_stacks(:review_stack_active)    # not archived, belongs to org_b_repo

  payload = {
    action: "unlabeled",
    number: org_b_stack.pull_request.number,
    pull_request: {
      id: 1, number: org_b_stack.pull_request.number, url: "https://api.github.com/x",
      title: "x", state: "open", additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "some-branch" },
      user: { login: "attacker" },
      assignees: [],
      labels: [] # no provisioning label -> archive! fires
    },
    repository: { full_name: org_b_repo.full_name, owner: { login: org_a } },
    sender: { login: "attacker" }
  }.to_json

  assert_not org_b_stack.reload.archived?

  post "/webhooks", params: payload,
    headers: { "X-Github-Event" => "pull_request", "X-Hub-Signature" => "sha1=deadbeef",
               "Content-Type" => "application/json" }

  assert_response :ok
  assert_not org_b_stack.reload.archived?,
    "org_b's stack was archived by a request verified under org_a's (missing) secret — cross-tenant binding is broken"
end
```
Before the fix: `org_b_stack.archived?` flips to `true` even though the request was verified under `org_a`'s (blank) secret and org A has no relationship to org B — demonstrating the equality `verifying_org == owning_org_of(target_stack)` does not hold. After adding a cross-field check (`repository.owner.login` must match the owner segment of `repository.full_name`, and the request must be rejected when the owner-derived org's secret is blank/spoofable), the assertion passes.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-69)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-68)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
