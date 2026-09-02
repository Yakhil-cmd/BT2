### Title
Webhook signature-verification failure does not halt request processing, allowing unauthenticated `membership` events to escalate `Shipit.github_teams` authorization - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` responds with `head(422)` when the `X-Hub-Signature` fails verification, but never halts the Rails filter chain (no `throw(:abort)` / early `return`). Because of this, the `create` action still runs and dispatches the raw, unverified JSON payload to the registered webhook handlers before the controller ultimately double-renders and errors out. This lets an unauthenticated network attacker post a forged `membership` webhook that creates/updates `Shipit::Team` and `Shipit::Membership` records, which are the exact objects `User#authorized?` consults to gate access via `Shipit.github_teams`.

### Finding Description
`verify_signature` is a `before_action` that only calls `head(422)` on failure, it does not `throw(:abort)` or `return false`: [1](#0-0) 

In Rails, calling `head`/`render` inside a `before_action` does not by itself halt the callback chain — subsequent filters and the action still execute, and a later attempt to render raises `AbstractController::DoubleRenderError`, but only after the earlier code already ran. The `create` action processes and dispatches the payload to all registered handlers before it attempts its own `head(:ok)`: [2](#0-1) 

The signature failure therefore does not stop `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` from executing on a payload whose signature was rejected — breaking the binding "payload field acted on == payload field covered by verified signature."

The `membership` event is wired to `Handlers::MembershipHandler` by default: [3](#0-2) 

Existing tests confirm this handler creates `Team` records on the fly and adds/removes `Membership` records for arbitrary GitHub logins supplied in the payload (`test/controllers/webhooks_controller_test.rb`, `:membership` tests). These `Team`/`Membership` records are exactly what gates application authorization: [4](#0-3) [5](#0-4) 

### Impact Explanation
An attacker with no Shipit session, no `ApiClient` token, and no knowledge of `webhook_secret` can send a `membership` (or any other registered) webhook event with an invalid/absent `X-Hub-Signature` directly to the public `/webhooks` endpoint. Because signature verification failure does not halt request handling, the handler still executes and mutates `Team`/`Membership` state before the eventual double-render error is raised. By adding a controlled GitHub login to a `Team` referenced in `Shipit.github_teams`, the attacker can grant that login (and thus a colluding/compromised account performing normal GitHub OAuth login) authorized access to the Shipit application — an escalation into `Shipit.github_teams` authorization performed without ever possessing the webhook secret. This satisfies the High-severity criterion "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
High. The `/webhooks` endpoint is intentionally public and unauthenticated by design (it exists to receive GitHub callbacks), so the attacker only needs network reachability to the deployment, no credentials of any kind. The bug is a straightforward Rails filter-halting mistake (missing `throw(:abort)`/`return`) that is trivial to trigger by simply omitting/forging the `X-Hub-Signature` header.

### Recommendation
In `app/controllers/shipit/webhooks_controller.rb#verify_signature`, explicitly halt the callback chain on failure, e.g. `head(422) and return` / `throw(:abort)` in every failure branch (both the `unless verified` case and the `rescue Shipit::GithubOrganizationUnknown` case), so that the `create` action and all webhook handlers never run against a payload whose signature could not be verified.

### Proof of Concept
1. `POST /webhooks` with header `X-Github-Event: membership`, no or an invalid `X-Hub-Signature` header, and a JSON body such as:
```json
{
  "action": "added",
  "team": {"id": 48, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://example.com"},
  "organization": {"login": "attacker-controlled-or-known-org"},
  "member": {"login": "attacker_github_login"}
}
```
2. `verify_signature` runs, `verify_webhook_signature` returns `false`, `head(422)` is called but the filter chain is not halted.
3. `create` runs anyway: `Shipit::Webhooks.for_event('membership')` resolves to `MembershipHandler`, which creates the `Team` (if unknown) and a `Membership` row binding `attacker_github_login` to that team — matching the behavior exercised in `test/controllers/webhooks_controller_test.rb` `":membership creates the mentioned team on the fly"` / `":membership can append an user membership"`.
4. If that team's handle is present in `Shipit.github_teams` (an app operator's configured authorization list), the attacker-controlled login is now considered a member of an authorizing team, per `User#authorized?` at [4](#0-3) , granting it access through `force_github_authentication` at [5](#0-4) .

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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
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
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
