### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while event handlers act on the unrelated `repository.full_name` field, allowing cross-repository webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` is used to validate the HMAC signature based on `repository.owner.login` (falling back to `organization.login`), but every webhook handler (e.g. `PushHandler`) determines the Shipit `Repository`/`Stack` to act on using the completely independent `repository.full_name` field, which is never covered by the signature check. An attacker who controls one legitimate GitHub App/organization onboarded to a multi-tenant Shipit instance can forge a webhook payload that is validly signed for their own organization while targeting an arbitrary other repository's Stack.

### Finding Description
`verify_signature` computes the signing organization from the payload and validates the signature against that organization's `webhook_secret`: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` supports multiple independently configured GitHub Apps/organizations, each with its own `webhook_secret` (confirmed by the multi-app test fixture and `ShipitTest#".github uses indifferent access to search through the Github applications"`).

Once the signature check passes for *that* organization, the raw `params` are dispatched unchanged to the handler(s) for the event: [3](#0-2) 

Every handler (e.g. `PushHandler`) resolves the target Stack(s) via `Handler#stacks`, which reads `repository.full_name` — a field completely different from, and never cross-checked against, `repository.owner.login`/`organization.login` used during signature verification: [4](#0-3) [5](#0-4) 

This is the same class of bug as the referenced report: two fields that are supposed to refer to the same logical entity (here, "the repository/organization whose credential authenticated the request" vs. "the repository the code actually writes to") are read from unrelated locations without being tied together, so an attacker can supply values that diverge. Concretely: the equality `verified_organization(repository.owner.login) == acted_repository(repository.full_name)` is never enforced.

### Impact Explanation
An organization/app already onboarded to a shared Shipit instance (a normal, unprivileged multi-tenant scenario the engine itself supports via `Shipit.github(organization:)`) knows its own `webhook_secret`. Using that secret, the attacker can sign an arbitrary payload where `repository.owner.login`/`organization.login` is set to their own org (so the correct/known secret is used and verification succeeds) while `repository.full_name` is set to any other repository/stack tracked by the same Shipit instance. Because handlers key off `full_name` alone, this results in cross-repository writes: e.g. `PushHandler` will enqueue `stack.sync_github(expected_head_sha: params.after)` for a victim repository/stack using an attacker-chosen `after` SHA, and other handlers deriving from `Handler#stacks` (status, commit_status, deployable_status, merge_status, pull_request-related handlers) are equally exposed to acting on a repository the attacker does not own. This satisfies the Critical "cross-repository writes" / "unauthorized deploy/rollback" impact bar, since sync/status manipulation can influence deploy eligibility and undeployed-commit tracking on a repository the attacker never controls.

### Likelihood Explanation
High: the only prerequisite is that the attacker's own organization/app already has a webhook_secret configured in the same Shipit deployment (a normal, unprivileged tenant of a multi-org Shipit install, not requiring any elevated credentials, GitHub App private key, or session), plus knowledge of the target repository's `full_name`, which is public information. No interaction with the victim's webhook secret or GitHub account is required.

### Recommendation
Bind the two fields together: after selecting the signing organization from `repository.owner.login`/`organization.login`, verify that this same value matches the owner segment of `repository.full_name` (or, more robustly, resolve the target `Repository`/`Stack` using the verified organization rather than trusting the payload's `full_name` independently). Reject the webhook if the two do not match.

### Proof of Concept
1. Shipit is configured with two GitHub Apps/organizations, `attacker-org` (secret known to the attacker, who legitimately administers that org's Shipit integration) and `victim-org` (repository `victim-org/victim-repo` tracked by Shipit with an existing Stack).
2. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret>` over the raw JSON body.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `GithubApp`, and successfully verifies the signature. [1](#0-0) 
5. `PushHandler.call(params)` runs, resolving `repository_name` as `"victim-org/victim-repo"` and triggering `sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim's stacks — even though the signature was never validated against victim-org's secret. [4](#0-3) [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
