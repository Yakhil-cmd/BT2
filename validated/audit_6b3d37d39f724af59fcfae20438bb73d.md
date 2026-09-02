### Title
Cross-repository `Status` forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` poisons `Commit#deployable?` for unrelated stacks - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits to attach a forged CI `Status` to using only the SHA from the incoming webhook payload, with no check that the sha belongs to the repository that the (correctly) verified webhook signature vouches for. Every other handler in the same directory (`CheckSuiteHandler`, push/pull_request handlers) scopes its writes through `Handler#stacks`, which resolves `Stack`s via `Repository.from_github_repo_name(repository_name)` - `StatusHandler` skips this scoping entirely.

### Finding Description
The broken binding: `repository_owner (verified by signature) == repository owning the commit that receives the Status` is assumed true by `StatusHandler#process` but is never enforced in code.

- `WebhooksController#verify_signature` only proves the webhook was validly signed for `repository_owner` (`params.dig('repository','owner','login')`), i.e. it proves "this event genuinely comes from GitHub for org/repo X." [1](#0-0) 
- `StatusHandler#process` then does `Commit.where(sha: params.

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
