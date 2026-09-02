## Analysis

I found a genuine binding break in `Shipit::WebhooksController`, confirming this analog is valid: it deploys the same "value computed from an incomplete/wrong subset of state" bug class from the report — here, the **organization whose credentials authenticate the webhook signature is not the same organization/repository the event handlers subsequently act on.**

### Title
Webhook signature is verified against the organization derived from an unauthenticated payload field, while handlers act on a different repository field never covered by that binding - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App / webhook secret to check the HMAC signature against using `repository_owner`, computed from the raw JSON body itself (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). In multi-organization installations (`Shipit.github_organizations`, `lib/shipit.rb`), each org has its own `webhook_secret`. The signature check only proves the request was signed by *that org's* secret — it does not verify that the `repository.full_name` the handlers subsequently operate on (`Shipit::Webhooks::Handlers::Handler#repository_name`, `app/models/shipit/webhooks/handlers/handler.rb:36-38`) actually belongs to the same organization used for verification.

### Finding Description [1](#0-0)  shows `verify_signature` builds `github_app` from `Shipit.github(organization: repository_owner)` and validates the raw body's HMAC using that org's secret via `verify_webhook_signature`. `repository_owner` is read straight out of the untrusted, attacker-controlled JSON body: [2](#0-1) 

Once verification passes, the full `params` (parsed independently again from `request.raw_post`) are dispatched to handlers: [3](#0-2) 

Handlers resolve the target `Stack`/`Repository` from `payload.dig('repository', 'full_name')`, a *different* JSON field than the one used to select the verification org: [4](#0-3) 

The equality that should hold is:
`organization used to verify_webhook_signature == organization owning the repository.full_name the handler writes to`

Since both fields live in the same attacker-controlled JSON body and only `repository.owner.login`/`organization.login` is used for key selection, an attacker who can produce a signature valid for *any one* configured organization (e.g. because that org's `webhook_secret` is blank/unset — `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank, per `lib/shipit/github_app.rb:76-83`) can set `repository.owner.login` to that org while setting `repository.full_name` to point at a stack belonging to an entirely different, properly-secured organization. The signature check passes (org A has no secret), but the handler acts on org B's repository/stack because `repository_name` is read from a separate, unchecked field.

### Impact Explanation
This breaks the binding between "the organization whose credential authorized this webhook" and "the repository/stack that gets mutated." Depending on the handler dispatched (`push`, `status`, `check_suite`, `pull_request`, `membership`), this can trigger `GithubSyncJob`, commit status updates, review-stack archive/unarchive, or team/membership changes against a stack that belongs to a different, unrelated GitHub organization/repository than the one that actually authenticated the request — an unauthorized cross-repository state change without possessing that repository's real webhook secret. This matches the "cross-repository writes" / "unauthorized deploy" impact class (continuous delivery can be triggered via `push`/`status` handlers advancing deploys).

### Likelihood Explanation
Likelihood depends on operational configuration: it requires either (a) a multi-org Shipit install where at least one configured organization has an empty/missing `webhook_secret` (explicitly supported, since `verify_webhook_signature` treats blank secret as "always verified"), or (b) knowledge of one org's real webhook secret while targeting another org's stack. Given `docs/setup.md` calls the webhook secret "optional," an operator populating one org strictly while leaving another default/unset is plausible, making this reachable purely as an unauthenticated attacker (no session, no API token, no repository write access) who simply crafts a raw HTTP POST to `/webhooks`.

### Recommendation
Verify the signature using the *same* repository/organization field that handlers use to resolve targets (`repository.full_name`'s owner), and reject organizations configured with a blank `webhook_secret` in multi-organization mode instead of silently returning `true`. Additionally, cross-check that the org used to select the verification key matches the owner implied by `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `orgA` (no `webhook_secret` set) and `orgB` (properly configured with stacks/repositories).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/some-repo" },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/main"
}
```
3. `verify_signature` calls `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/garbage) `X-Hub-Signature` header.
4. `Shipit::Webhooks.for_event('push')` handler resolves the target repository via `payload.dig('repository','full_name')` = `"orgB/some-repo"`, enqueuing `GithubSyncJob` against `orgB`'s stack — despite the request never being authenticated by `orgB`'s secret.

*Note: full confirmation that the `push` handler's exact implementation matches `Handler#repository_name` (vs. a bespoke lookup) and the exact `Shipit::Webhooks` dispatch table were not directly inspected in this pass; the shared `Handler` base class and multiple concrete handlers (`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) confirmed use `payload.dig('repository','full_name')` exclusively, independent of the field used for signature-key selection.*

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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
