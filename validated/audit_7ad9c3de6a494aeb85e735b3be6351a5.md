### Title
Unauthenticated actor forgery via `sender.login` in `ReviewStackAdapter#user` used by `stack.archive!`/`stack.unarchive!` - (File: `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb`)

### Summary
`ReviewStackAdapter#user` resolves the actor for `stack.archive!`/`stack.unarchive!` solely from `params.sender["login"]`, a plain string field inside the webhook JSON body, with no check that this value corresponds to any authenticated Shipit session, `ApiClient`, or the GitHub identity that actually triggered the event. Combined with the cross-org repository-confusion precondition (payload where `repository.owner.login` matches the attacker's own configured webhook secret while `repository.full_name` names a victim repository/stack), an attacker who can get one syntactically valid signed webhook accepted can also freely choose the `sender.login` value that becomes the recorded actor of the archive/unarchive action.

### Finding Description
The intended binding is:
`recorded_actor_of(stack.archive!) == github_identity_authenticated_for_this_request`

The actual code breaks this binding: `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter#user` at [1](#0-0) 
does `Shipit::User.find_or_create_by_login!(params.sender["login"])`, and `#archive!` passes this straight into `stack.archive!(user, ...)`: [2](#0-1) 

`Shipit::User.find_or_create_by_login!` will find an existing user by that login or create one, in the latter case even fetching the real GitHub profile via `Shipit.github.api.user(login)`: [3](#0-2) 
So if the attacker names a real, privileged operator's GitHub login, that operator's actual `Shipit::User` record (or a newly created record populated with their real GitHub profile data) becomes the actor of the archive action.

`Shipit::WebhooksController#verify_signature` only validates the HMAC over the *entire* raw JSON body against the webhook secret configured for the organization inferred from `repository.owner.login`/`organization.login` in that same body: [4](#0-3) 
It performs no cross-field validation that `repository.full_name`, `sender.login`, or any other field is internally consistent or truthful — it merely proves the body was signed with *some* secret Shipit trusts for the org named in the signature-selection field. Nothing in `ClosedHandler`/`LabeledHandler`'s `ExplicitParameters` schema constrains `sender.login` beyond "is a String": [5](#0-4) [6](#0-5) 

Given the precondition that the attacker can get such a payload accepted for a repository/stack they do not own (the cross-org repository-confusion scenario), they fully control every field of that signed body, including `sender.login`. There is no code path anywhere between the webhook controller and `ReviewStackAdapter#user` that ties `sender.login` to a `session[:user_id]`, an `ApiClient`, or any authenticated Shipit identity — it is trusted at face value as "who did this."

### Impact Explanation
Any attacker able to trigger the underlying cross-tenant archive/unarchive primitive can additionally choose an arbitrary named actor for that mutation — including impersonating/framing a real, privileged Shipit operator whose GitHub login is public. The forged actor is persisted as the recorded actor of `Stack#archive!`/`#unarchive!` (audit trail / comment attribution), and if the named user did not previously exist in Shipit, their real GitHub profile is fetched and a genuine `Shipit::User` record is created and permanently bound to an action they never performed. This is repeatable against any repository/stack reachable by the underlying cross-org confusion and against any named GitHub login, so the blast radius spans arbitrary victim tenants and arbitrary victim identities. This qualifies as Critical per the stated impact rubric ("a payload for one repository mutating another's stack ... combined with) an audit-log/actor-attribution forgery.

### Likelihood Explanation
The attacker needs no Shipit session, API client, or secrets — only the ability to (a) trigger the cross-org repository-owner/full_name confusion already covered by the ClosedHandler/LabeledHandler precondition, and (b) know or guess a target GitHub login (trivially discoverable, since GitHub logins are public). No additional Shipit-side configuration is required beyond what the precondition scenario already needs. Cost is a single crafted HTTP POST to `/webhooks`; the exploit is deterministically repeatable for any repository/stack and any target login.

### Recommendation
Do not derive the audit-trail actor from unauthenticated payload fields. For webhook-driven actions, either (a) record a fixed system/bot actor (e.g., a dedicated "GitHub Webhook" service user) instead of resolving an arbitrary login from the payload, or (b) cryptographically bind `sender.login` to the specific event's `sender.id`/`sender.node_id` and cross-validate it against GitHub's API for that specific delivery, and additionally fix the root cause by ensuring `repository.owner.login` (used for signature-secret selection) is cross-checked against `repository.full_name` before any handler resolves a repository/stack from the payload.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/review_stack_adapter_actor_forgery_test.rb
test "archive! records an arbitrary sender.login as actor with no authenticated session" do
  victim_stack = shipit_review_stacks(:some_open_review_stack) # belongs to victim org/repo

  forged_login = "trusted-shipit-operator" # a real operator's public GitHub login
  params = ExplicitParameters::Params.new(
    action: "closed",
    number: victim_stack.pull_request.number,
    pull_request: { ... head: { ref: victim_stack.branch }, user: { login: "attacker" } },
    repository: { full_name: victim_stack.repository.full_name },
    sender: { login: forged_login }
  )

  adapter = Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter.new(
    params, scope: victim_stack.repository.review_stacks
  )

  assert_no_difference -> { Shipit::User.exists?(login: forged_login) } # attacker never authenticated as this user
  adapter.archive!

  actor = adapter.user
  assert_equal forged_login, actor.login
  # No Shipit session or ApiClient exists for this identity for this request:
  assert_nil Shipit::User.find_by(login: forged_login)&.github_access_token
  # The stack's archive event is attributed to `actor`, not to any authenticated caller
  assert_equal actor, victim_stack.reload.archive_comment&.actor # or equivalent actor accessor
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L52-54)
```ruby
          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end
```

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L36-38)
```ruby
            requires :sender do
              requires :login, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L36-38)
```ruby
            requires :sender do
              requires :login, String
            end
```
