### Title
Webhook status events are applied by commit SHA across all organizations without verifying the SHA belongs to the signing organization's repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks *which* GitHub organization's `webhook_secret` to validate a webhook against using a value derived from the payload body itself, but the event handler that actually mutates data (`StatusHandler`) never re-checks that binding — it looks up the target `Commit` purely by `sha`, globally, across every repository/organization hosted on the same Shipit instance. This breaks the equality "organization whose secret verified the signature == organization whose stack/commit is written."

### Finding Description
`WebhooksController#verify_signature` derives the organization used to select the HMAC secret from the payload itself: [1](#0-0) [2](#0-1) 

The secret lookup is `Shipit.github(organization: repository_owner)`, and `github_app.verify_webhook_signature` HMACs the *raw body* against that org's configured `webhook_secret`: [3](#0-2) 

This proves only that *some* value inside the signed body determined which secret was used — it does not prove that the rest of the payload (in particular the `sha` a status event targets) belongs to that same organization's repositories.

Once the signature check passes, `Shipit::Webhooks.for_event(event)` dispatches to `StatusHandler#process`, which resolves the target purely by commit SHA, with no repository/organization scoping at all: [4](#0-3) 

Compare this to `Handler#stacks`, which *does* scope lookups by `repository.full_name` for other handlers (e.g. `PushHandler`): [5](#0-4) [6](#0-5) 

`StatusHandler` does not use this scoping mechanism at all. Because Shipit explicitly supports multiple GitHub organizations sharing one instance (each with its own `webhook_secret`, as seen in `config/secrets.development.shopify.yml`), an actor who legitimately controls (or is a member of) **any one** onboarded organization can send a correctly-signed `status` webhook for their own org, but populate `sha`/`state`/`target_url`/`context` fields that reference a commit belonging to a **different** organization's stack — as long as they can learn or guess that commit's SHA (trivially available, since commit SHAs of public/private-but-visible-to-collaborators repos are routinely exposed via PR links, CI logs, etc.). `StatusHandler` will happily attach the forged status to that unrelated commit.

This is precisely the "binding break" class described by the report: a value that authorizes an action (organization identity, verified via signature) is not the same value that scopes the action actually performed (arbitrary commit by SHA, with no organization/repository check), analogous to an `immutable` value being fixed for the wrong context, or a check being performed on one field while a different, unguarded field drives the real effect.

### Impact Explanation
Commit statuses are used by Shipit to gate deploy safety and the merge queue via "blocking statuses" (`app/models/shipit/status/group.rb`, `app/models/shipit/deploy_spec.rb`, `app/models/shipit/merge_request.rb`). By forging a `success` status on a victim organization's commit from an attacker-controlled organization's authenticated webhook channel, an attacker can mark blocking CI checks as green for a repository they do not own, potentially enabling an unauthorized merge via the merge queue or clearing a deploy-safety gate — landing in the "Critical: cross-repository writes... or an unauthorized deploy, rollback or merge" bucket.

### Likelihood Explanation
This requires no privileged Shipit session, `ApiClient` token, or GitHub App private key — only the ability to have one's own organization onboarded to the multi-org Shipit instance (a normal, documented, unprivileged setup path) and knowledge of a target commit's SHA, which is public/discoverable information for any repository the attacker can view (e.g. via PR pages, CI badges). The write path (`StatusHandler#process`) performs no repository/organization scoping whatsoever, making exploitation deterministic once the SHA is known.

### Recommendation
Scope `StatusHandler#process` (and any other handler that doesn't already do so) to the repository identified by the payload's `repository.full_name`, and cross-check that this repository's owner matches the organization whose `webhook_secret` verified the request, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
```
More generally, `verify_signature` should establish a single canonical "authenticated organization" for the request, and every handler should be required to prove the entities it mutates (`Commit`, `Stack`, `Repository`, `Team`) belong to that organization before acting, instead of independently trusting individual payload fields.

### Proof of Concept
1. Attacker is a member of (or administers) `org-attacker`, a GitHub organization legitimately onboarded to the shared Shipit instance, and knows `webhook_secret` for `org-attacker` (they configured it themselves when adding the webhook).
2. Attacker learns the SHA of a commit `abcd1234` on `org-victim/private-repo`'s stack (visible to them via a shared PR link, CI badge, or any read access to that repo).
3. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body:
```json
{ "sha": "abcd1234", "state": "success", "context": "ci/required-check", "target_url": "https://ci.example.com/ok",
  "repository": { "owner": { "login": "org-attacker" } } }
```
   signed with `org-attacker`'s `webhook_secret`.
4. `verify_signature` resolves `repository_owner` = `"org-attacker"`, verifies successfully against `org-attacker`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: "abcd1234")`, finds the victim's commit (since SHA lookup is global, unscoped to `org-attacker`), and calls `create_status_from_github!`, marking the victim's blocking check as `success` — potentially unlocking a deploy or merge on `org-victim`'s stack that the attacker has no authorization over.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
