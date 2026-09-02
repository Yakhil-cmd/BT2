### No vulnerability found for this question.

The entire premise depends on the attacker being able to deliver a "forged membership webhook" that reaches `MembershipHandler#process`. That never happens without a valid GitHub webhook signature.

`Shipit::WebhooksController` runs `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` before `create` is invoked [1](#0-0) . `verify_signature` computes `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` for the organization derived from the payload and calls `head(422)` if it fails [2](#0-1) . This check happens strictly before `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is ever reached in `create` [3](#0-2) , and Rails before_actions that call `head`/render halt the filter chain, so `create` (and therefore `MembershipHandler#process`) is never executed for an unsigned or incorrectly signed request.

Per the stated attacker model, the attacker holds no `webhook_secret` and no ability to compute a valid `X-Hub-Signature` for `organization: 'shopify'` (or whatever org the target `Team#organization` belongs to). Without that secret, `verify_webhook_signature` will return `false` for any payload the attacker crafts, and the request is rejected with `422` before `MembershipHandler#process` — and hence `team.add_member` — can run [4](#0-3) .

Since the attacker can never get a forged `membership` payload past `verify_signature`, there is no race to win against `Team#refresh_members!`'s `self.members = members; save!` sequence [5](#0-4) , regardless of ActiveRecord's `has_many through:` assignment semantics or timing. The TOCTOU window described in the question is unreachable under the given threat model — it would only matter for an attacker who already possesses `github.webhook_secret` for the organization, which is explicitly out of scope ("no ... `webhook_secret`").

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```

**File:** app/models/shipit/team.rb (L45-51)
```ruby
    def refresh_members!
      github_api = Shipit.github(organization:).api
      github_members = Shipit::OctokitIterator.new(github_api.get(api_url).rels[:members])
      members = github_members.map { |u| User.find_or_create_from_github(u) }
      self.members = members
      save!
    end
```
