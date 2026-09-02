### Title
Webhook signature verification is keyed off an attacker-controlled organization field, allowing signature bypass for any org that has no `webhook_secret` configured, and forged events are then applied to a *different*, attacker-chosen repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` decides *which* per-organization secret to check the HMAC signature against by reading an unauthenticated field straight out of the untrusted request body (`repository.owner.login` / `organization.login`), before any signature has been verified. `GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatic success. Every downstream webhook handler then acts on a completely independent field of the same untrusted body - `repository.full_name` - to decide which `Stack`/`Repository`/`Team` to mutate. This breaks the binding "organization that authenticated == repository/team that is written": the org used to pick (or skip) the secret check is not the same value used to select the object that gets mutated.

### Finding Description
`verify_signature` resolves the organization purely from the JSON body: [1](#0-0) [2](#0-1) 

The signature check itself is a no-op when that organization's app config has no `webhook_secret`: [3](#0-2) 

Meanwhile, every `Handler` subclass resolves the affected `Repository`/`Stack` from a *different* field of the same body, `repository.full_name`, independent of which organization's secret was (or wasn't) checked: [4](#0-3) 

Because `params` is attacker-controlled JSON on an unauthenticated public endpoint (`skip_before_action :verify_authenticity_token`, no session/API-token requirement before `verify_signature` runs): [5](#0-4) 

an attacker can craft a payload where `repository.owner.login` (or `organization.login`) names an organization whose Shipit GitHub App config has no `webhook_secret` set - a state the code explicitly anticipates and accepts ("`return true unless webhook_secret`") - while `repository.full_name` names a repository belonging to an entirely different, properly-secured organization. `verify_signature` passes (secret-less org => automatic success), and the handler then acts on the named `repository.full_name`, e.g. resolving `Repository.from_github_repo_name(repository_name)` to locate real stacks belonging to the *other* org.

This is precisely the pattern called out by the review criteria: "an organization that authenticated versus the repository that is written". The equality that should hold - `organization_whose_secret_was_verified == organization_owning_the_repository_being_mutated` - does not, because the two values are independently attacker-supplied and never cross-checked against each other.

### Impact Explanation
Depending on the event type, this allows:
- Forged `push` events to trigger `GithubSyncJob` against a targeted stack's repository, or forged `status`/`check_suite` events to alter what the app believes about a commit's CI state.
- Forged `membership` events to create Teams/Memberships on the fly (test evidence shows the handler creates a `Team`/`Membership` purely from unauthenticated payload fields): [6](#0-5) 
If the created/added team matches one of `Shipit.github_teams`, this is a direct escalation into `Shipit.github_teams` authorization used by `Authentication#force_github_authentication` / `User#authorized?` (`app/controllers/concerns/shipit/authentication.rb`, `app/models/shipit/user.rb`), which is explicitly listed as a High-severity impact.
- Combined with `continuous_deployment`, a forged successful `status`/`check_suite` webhook for a chosen commit could make that commit appear deployable and feed `Stack.schedule_continuous_delivery` / `trigger_continuous_delivery`, resulting in an unauthorized deploy - a Critical-severity impact.

### Likelihood Explanation
Exploitability only requires: (1) the deployment to have at least one configured GitHub organization without a `webhook_secret` (an explicitly supported, non-error configuration in this code, not a documented "don't do this"), and (2) network access to the public `/webhooks` endpoint - no session, API token, or repository write access is needed, matching the "unprivileged attacker" requirement. Multi-organization Shipit installations where only some orgs configure `webhook_secret` are plausible in practice (e.g., staging/internal orgs left unconfigured).

### Recommendation
- Do not let an unauthenticated field select which secret validates the request. Verify the signature against every configured organization's secret (or a global default) before trusting any field of the payload, and reject the request if no configuration can produce a valid signature.
- After a signature is validated for organization `O`, enforce that the `repository.full_name` / `organization.login` used by the handler belongs to `O` (cross-check owner login against the resolved app configuration) before performing any lookup or mutation.
- Treat a missing `webhook_secret` as "reject all webhooks for this organization" rather than "accept unconditionally," or require `webhook_secret` to be present for any organization capable of resolving to a real `Stack`.

### Proof of Concept
1. Configure Shipit with two GitHub App entries: `org-empty` (no `webhook_secret`) and `org-real` (has a `webhook_secret`, owns a real `Stack` for `org-real/app`).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "organization": { "login": "org-empty" },
  "team": { "id": 1, "name": "Deployers", "slug": "deployers", "url": "https://example.com" },
  "member": { "login": "attacker-controlled-login" },
  "sender": { "login": "attacker" }
}
```
No `X-Hub-Signature` header is required: `verify_webhook_signature` returns `true` because `org-empty` has no `webhook_secret` (`lib/shipit/github_app.rb:76-77`).
3. The `membership` handler creates the `deployers` Team and adds `attacker-controlled-login` as a member, exactly as demonstrated in `test/controllers/webhooks_controller_test.rb:129-149`. If `deployers` matches an entry in `Shipit.github_teams`, and that GitHub login is later used to authenticate to the Shipit UI, `User#authorized?` succeeds even though the attacker was never actually granted membership on GitHub.
4. Similarly, a `push`/`status` payload can set `repository.owner.login` to `org-empty` while `repository.full_name` to `"org-real/app"`, bypassing signature verification and causing handlers to act on `org-real`'s real stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-16)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** test/controllers/webhooks_controller_test.rb (L129-149)
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
```
