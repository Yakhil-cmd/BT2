### Title
`GitHubApp#verify_webhook_signature`'s unconditional early-return for secretless orgs creates an observable 422-vs-200 oracle that lets an attacker enumerate which configured GitHub organizations accept forged webhooks - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` resolves the GitHub App config for `repository_owner` via `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature`. Unknown organizations raise `Shipit::GithubOrganizationUnknown`, which is rescued and answered with `head(422)`, while organizations that resolve but have no `webhook_secret` configured hit `return true unless webhook_secret` in `verify_webhook_signature` and fall through to a `200 OK` from `create`. This status-code divergence lets an unauthenticated caller cheaply distinguish "unknown org" from "known org with no signature check," directly identifying which configured orgs will accept an arbitrarily-forged webhook payload.

### Finding Description
Binding claimed to hold: `response_status(org) == response_status(org')` for any two organization names `org`, `org'` submitted with an invalid/garbage signature, regardless of whether the org is unconfigured vs. configured-but-secretless. Tracing the code shows this binding is false.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (attacker-controlled JSON body, no signature validated yet) and calls `Shipit.github(organization: repository_owner)`.
- If `repository_owner` does not match any key in `Shipit.github_config`, `Shipit.github` raises `Shipit::GithubOrganizationUnknown`, caught at line 39, producing `head(422)`.
- If `repository_owner` matches a configured org, `github_app.verify_webhook_signature(signature, raw_post)` is called. In `lib/shipit/github_app.rb:76-83`, `return true unless webhook_secret` means any org entry in `Shipit.github_config` that has no `webhook_secret` key set always returns `true`, **without ever computing or comparing an HMAC**, regardless of the (attacker-supplied, possibly garbage) `X-Hub-Signature` header.
- When `verify_webhook_signature` returns `true`, `verify_signature` does not call `head`, so the `before_action` chain proceeds to `create`, which parses `params` and dispatches to `Shipit::Webhooks.for_event(event)` handlers, ultimately returning `head(:ok)` (200).

Consequently, sending the same malformed/garbage signature with different `repository.owner.login` values yields **422** for unconfigured orgs and **200** for configured-but-secretless orgs. This is a clean, unauthenticated oracle: no session, API token, or GitHub secret is needed to run it, and it can be repeated against every org name of interest. No existing guard (`drop_unhandled_event`, `check_if_ping`, `ExplicitParameters`, `force_github_authentication`, model validators) inspects or normalizes this status-code difference; the divergence is intrinsic to `verify_webhook_signature`'s early-return design and the controller's exception-vs-return-value duality.

### Impact Explanation
An attacker can, with cheap unauthenticated HTTP probing, precisely identify which of the operator's configured GitHub organizations have no `webhook_secret` set, i.e. which orgs will accept a fully-forged webhook payload (arbitrary `repository.full_name`, `pull_request` body, commit SHAs, labels, etc.) with no signature check at all. That forged-webhook acceptance is itself the Critical-impact primitive ("authentication bypass (forged webhook ... accepted)") because handlers under `Shipit::Webhooks.for_event(event)` act on payload data to mutate stack/commit/task state for whatever repository/org the attacker names in the payload. The status-code oracle turns a blind guess-and-check into a targeted, low-cost reconnaissance step against every org name the attacker can enumerate (e.g., org names culled from public GitHub), letting them focus the cross-repo forgery exclusively on orgs proven secretless. This is repeatable indefinitely and scales across every tenant/org configured in `Shipit.github_config`.

### Likelihood Explanation
Preconditions: the Shipit deployment must have at least one org entry in `Shipit.github_config` without a `webhook_secret` (an intentional or accidental operator configuration choice) alongside other orgs that are either unconfigured or have secrets set. No Shipit session, API token, GitHub App key, or `webhook_secret` is required by the attacker — only the ability to POST to the public `/webhooks` endpoint with a crafted JSON body and a `X-Github-Event` header, which is explicitly in the unprivileged attacker's capability set. The probing cost is a handful of HTTP requests per candidate org name, entirely feasible and repeatable.

### Recommendation
Make the webhook-signature-verification failure path status-independent of organization lookup outcome and of secretless-org handling:
- Return the same status (e.g., always `422`, with no informative detail) for both `Shipit::GithubOrganizationUnknown` and any signature-verification failure, so unauthenticated callers cannot distinguish "unknown org" from "known org, bad/missing signature."
- More importantly, stop treating "no `webhook_secret` configured" as an implicit pass. `verify_webhook_signature` should not silently return `true`; either require `webhook_secret` to be present for all configured orgs (fail closed / raise a configuration error at boot), or explicitly document and enforce that secretless orgs must not process any event that can mutate state, closing the underlying forged-webhook-acceptance bug that this oracle is used to locate.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb` (existing file, extend it):

```ruby
test "signature verification status differs for unknown vs secretless orgs (oracle)" do
  # Stub Shipit.github_config to have:
  #   "known_no_secret" => { app_id: 1, installation_id: 1 } (no webhook_secret)
  #   ("totally_unknown_org" absent from config)

  post :create,
    body: { repository: { owner: { login: "totally_unknown_org" } } }.to_json,
    headers: { "X-Github-Event" => "push", "X-Hub-Signature" => "sha1=garbage" }
  assert_response 422 # Shipit::GithubOrganizationUnknown path

  post :create,
    body: { repository: { owner: { login: "known_no_secret" } } }.to_json,
    headers: { "X-Github-Event" => "push", "X-Hub-Signature" => "sha1=garbage" }
  assert_response 200 # verify_webhook_signature short-circuits true, garbage signature accepted
end
```

The two `assert_response` calls demonstrate the broken binding: identical garbage signatures produce different status codes (`422` vs `200`) purely based on whether the resolved org has `webhook_secret` configured, giving an attacker a working oracle with no privileged access.