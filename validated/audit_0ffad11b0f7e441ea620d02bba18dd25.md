### Title
Webhook signature verification is scoped to `repository.owner.login`, but stack lookup and downstream actions are scoped to the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based solely on `repository.owner.login` (or `organization.login`), while every handler that actually acts on the payload (`Handler#stacks`, used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the target `Repository`/`Stack` from a *different* field, `repository.full_name`. These two fields are never cross-validated against each other.

### Finding Description
`verify_signature` in [1](#0-0)  does:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
with `repository_owner` derived from [2](#0-1) :
```
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```

Once the signature is accepted, the full raw payload is dispatched to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) . Every built-in handler resolves the target stacks through `Handler#stacks`, which uses a *separate* field, `repository.full_name`:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end

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
