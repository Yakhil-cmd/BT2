### Title
Webhook Signature Is Verified Against `repository.owner.login`, But The State-Mutating Handler Acts On The Unverified `repository.full_name` Field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's webhook secret to validate the HMAC signature against using `repository.owner.login` (or `organization.login` as a fallback), [1](#0-0) [2](#0-1) . However, the handler that actually performs the state mutation (looking up and syncing `Stack`s) resolves the target repository from a *different* JSON field in the same payload, `repository.full_name`, via `Handler#repository_name`/`Handler#stacks` [3](#0-2) . Nothing in the signature verification binds `repository.owner.login` to `repository.full_name`, so an attacker who controls a legitimately onboarded organization (and therefore knows/controls that organization's own webhook secret) can forge a signed payload whose `repository.owner.login` matches their own org (passing signature verification) while `repository.full_name` names an entirely different, victim organization's repository.

### Finding Description
The binding that should hold is:
`organization authenticated by verify_webhook_signature == organization/repository whose Stacks are mutated by the handler`

Before the fix, these are computed from two independent, unauthenticated-at-verification-time payload fields:
- Authentication side: `repository_owner` = `params.dig('repository','owner','login') || params.dig('organization','login')`, used to pick which `Shipit.github(organization: ...)` webhook secret verifies the HMAC [1](#0-0) [2](#0-1) .
- Mutation side: `Handler#repository_name` = `payload.dig('repository','full_name')`, used by `Handler#stacks` to resolve `Repository.from_github_repo_name(repository_name)&.stacks`, which is exactly the object the handler (e.g. `PushHandler#process`) mutates via `stack.sync_github(expected_head_sha: params.after)` [3](#0-2) [4](#0-3) .

`verify_webhook_signature` in `GitHubApp` performs a straightforward per-organization HMAC-SHA1 check [5](#0-4) , and crucially `return true unless webhook_secret` — if the resolved organization has no configured secret, the signature check is a no-op. Even when a secret exists, the check only proves the payload was signed by *some* onboarded organization's secret (the one named in `repository.owner.login`); it says nothing about the truthfulness of `repository.full_name`, `organization.login` used elsewhere, or any other payload field consumed by the handlers (e.g. `MembershipHandler` trusts `params.organization.login` to attribute team ownership [6](#0-5) ).

An attacker who administers any GitHub organization/repository already connected to this Shipit instance (a normal, unprivileged prerequisite — anyone can set up a repo+webhook pointed at a shared Shipit deployment) knows or controls that organization's webhook secret and can produce a validly signed request. By setting `repository.owner.login` to their own organization (satisfying `verify_signature`) while setting `repository.full_name` to `"victim-org/victim-repo"`, they cause `PushHandler` to look up and sync a completely unrelated organization's `Stack`, without ever needing that organization's secret.

### Impact Explanation
This breaks the "organization authenticated versus repository written" binding explicitly called out as in-scope. Depending on the handler triggered, effects include:
- `push` events: forces `GithubSyncJob` to run against an arbitrary victim stack (`stack.sync_github`) [4](#0-3) , which can advance `last_deployed_commit`/trigger continuous-deployment logic on commits landing after a sync, resulting in an **unauthorized deploy** on the victim stack the attacker does not own.
- `status`/`check_suite` events analogously mutate commit state used to gate deployability for a victim's stack, again reached via the same `repository_name`-vs-`repository_owner` mismatch.

This satisfies the High-impact bar ("escalation into unauthorized deploy") without requiring a Shipit session, `ApiClient` token, or the victim organization's own webhook secret.

### Likelihood Explanation
Requires only that the attacker control any organization/repository already configured in the target Shipit instance (a normal, low-privilege setup step, not an admin/superuser capability on the Shipit application itself), plus the ability to craft/send an HTTP POST with a valid signature computed from their own secret. No GitHub App private key, `api_clients_secret`, or victim credentials are needed. This is a straightforward, reliably reproducible cross-tenant confusion once the two independent fields are understood, though it does require the deployment to host multiple organizations/repositories (a common Shipit multi-tenant use case).

### Recommendation
Bind the signature-verifying organization to the exact repository the handler will act on:
- In `WebhooksController#verify_signature`, do not fall back silently between `repository.owner.login` and `organization.login`; instead, after verification, re-derive `repository_name`/`organization` inside the handler using the *same* field that was authenticated, and reject the request if `repository.full_name`'s owner segment does not match the `repository.owner.login` (or `organization.login`) that was used to select the webhook secret.
- Alternatively, verify the signature using a secret scoped to the specific repository (not just organization), and assert equality between `repository.owner.login` and the owner prefix of `repository.full_name` before dispatching to any handler.

### Proof of Concept
1. Attacker owns `attacker-org/some-repo`, connected to the shared Shipit instance, with a known webhook secret `S_attacker`.
2. Victim's stack exists for `victim-org/victim-repo` on the same Shipit instance.
3. Attacker crafts a `push` payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha-that-exists-on-github>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(S_attacker, body)` and sends it with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC check passes because it was signed with `S_attacker` [1](#0-0) .
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack [3](#0-2) [4](#0-3) , mutating state the attacker was never authorized to touch.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
