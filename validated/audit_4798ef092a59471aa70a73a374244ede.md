### Title
Webhook signature-verification target organization is derived from the unverified payload, decoupling authenticated org from the repository actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GithubApp`/`webhook_secret` to use for HMAC verification based on `repository_owner`, a value read directly out of the **unverified** JSON body [1](#0-0) . That same call also determines whether verification is even enforced, because `GithubApp#verify_webhook_signature` unconditionally returns `true` when the selected organization has no `webhook_secret` configured [2](#0-1) . The event handlers that actually mutate state, however, resolve the target `Repository`/`Stack` from a *different* payload field, `repository.full_name` [3](#0-2) , via `Repository.from_github_repo_name` [4](#0-3) . Nothing ties the two fields together, so the organization whose credentials "authenticate" the request is not bound to the repository the handler subsequently writes to.

### Finding Description
The equality that should hold is: `organization used to select/enforce the webhook secret == organization that owns the repository the handler mutates`. This engine breaks that equality:

1. `repository_owner` is computed from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both are attacker-suppliable JSON fields in the raw POST body, read *before* any cryptographic check [1](#0-0) .
2. `verify_signature` uses that attacker-chosen string to fetch a `GithubApp` config via `Shipit.github(organization: repository_owner)` and only then attempts HMAC verification against `X-Hub-Signature` [5](#0-4) .
3. If the operator has configured any organization without a `webhook_secret` (a supported, non-error configuration state — the code path explicitly short-circuits rather than rejecting), verification is bypassed entirely for that organization: `return true unless webhook_secret` [6](#0-5) .
4. Once past `verify_signature`, `WebhooksController#create` dispatches the *entire attacker-controlled payload* to the matching handlers unmodified: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [7](#0-6) .
5. Handlers resolve the affected `Stack`/`Repository` from `payload.dig('repository', 'full_name')`, a field that was never checked against, nor required to match, the `repository.owner.login`/`organization.login` value used to select (and potentially bypass) the signature check [3](#0-2) .

Concretely, an attacker who can reach the public `/webhooks` endpoint can set `repository.owner.login`/`organization.login` to any organization name that Shipit has configured with a blank `webhook_secret` (satisfying the "authenticated org" side with zero cryptographic proof), while setting `repository.full_name` to any *other*, fully-secured stack's `owner/name` (the "repository written" side). The handler layer has no way to detect the mismatch because it never re-derives or cross-checks the owner used for verification.

The blast radius is not limited to push/status events. The existing test suite demonstrates that the `membership` event handler creates `Team` and `Membership`/`User` records purely from payload content (`team.id/name/slug`, `member.login`), with no relationship to a `Stack` at all [8](#0-7) . Since Shipit's authorization model (`Shipit.github_teams`) is driven by team/membership state synced through this same webhook path, a forged `membership` webhook — passed through the same signature-selection weakness — can inject or remove memberships used later for privilege decisions.

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding required by the engine's threat model. Concretely it enables:
- Forged webhook events (push/status/check_suite/membership) accepted as if from a legitimate, secured organization while actually targeting/mutating a different organization's `Stack` state, commit statuses, or CI signals used for deploy gating.
- Forged `membership` events letting an unprivileged external actor add or remove `Membership` rows, which feed directly into `Shipit.github_teams`-based authorization — an explicit High-impact category ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Exploitability depends on an operator having at least one configured GitHub organization/App entry without a `webhook_secret` set — a state the code treats as valid rather than rejecting (`return true unless webhook_secret`). Multi-tenant or staged Shipit deployments (multiple organizations configured, e.g. as exercised by `test/dummy/config/secrets_double_github_app.yml`) are the realistic case where this occurs. Given that condition, the exploit requires no Shipit session, no `ApiClient` token, and no GitHub credentials — only the ability to POST to the public webhook endpoint with a crafted JSON body.

### Recommendation
- Do not allow an organization to be configured with a blank `webhook_secret` as a way to skip verification; require an explicit, separate "unsigned webhooks allowed" opt-in instead of a silent bypass in `GithubApp#verify_webhook_signature`.
- Bind the organization used to select/enforce the webhook secret to the same value used by handlers to resolve the target repository. After signature verification, re-validate that `params.dig('repository','full_name')`'s owner segment matches the `repository_owner` that was used to select the verifying `GithubApp`, and reject on mismatch.

### Proof of Concept
1. Operator configuration contains two orgs: `org-a` (no `webhook_secret` set) and `org-b` (a real Shipit stack `org-b/prod-app` with a configured secret).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership` (or `push`) and a body:
```json
{
  "organization": { "login": "org-a" },
  "repository": { "full_name": "org-b/prod-app", "owner": { "login": "org-a" } },
  "action": "added",
  "member": { "login": "attacker" },
  "team": { "id": 1, "name": "deployers", "slug": "deployers" }
}
```
3. `repository_owner` resolves to `org-a` [1](#0-0) ; `Shipit.github(organization: 'org-a')` returns a `GithubApp` with `webhook_secret` blank, so `verify_webhook_signature` returns `true` with no valid `X-Hub-Signature` required [6](#0-5) .
4. `create` dispatches the payload to the `membership` handler, which creates/updates `Team`/`Membership` records exactly as shown in the existing tests, independent of `org-b`'s security posture [9](#0-8) .
5. Because the same decoupling exists for `push`/`status`/`check_suite` handlers (which key off `repository.full_name` via `Repository.from_github_repo_name`), the attacker can equally drive `GithubSyncJob`/status changes against `org-b/prod-app` while only ever satisfying `org-a`'s (absent) signature check.

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

**File:** test/controllers/webhooks_controller_test.rb (L129-165)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can delete an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, -1 do
        post :create, body: membership_params.merge(action: 'removed').to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can append an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end
```
