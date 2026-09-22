# Privacy before publication

Public PRs, comments and Git history are persistent. Deleting a file later does not undo a leak.

Agent workflow:
- Before inspecting a bank, identify what minimum fields the capability requires. Tell the account owner when their chosen cloud agent processes banking data; repository instructions do not authorize sharing data with unrelated services.
- Do not export whole HARs, cookie jars, browser profiles, account statements or agent transcripts into the repository. Raw local files belong only in ignored `.local/`, with restricted permissions and a deliberate cleanup plan.
- Prefer independently invented synthetic fixtures. For sanitized observations, replace names, account/routing IDs, transaction and organization IDs, dates, amounts, addresses, emails, references and free-text memos. Remove unrelated transactions, headers and metadata entirely. Preserve relevant sign, precision, duplicate/matching relationships and status behavior. Do not hash real low-entropy account identifiers as a substitute for redaction.
- Mark fixture provenance `synthetic` or `sanitized`; explain transformations and limitations. Never call sanitized bytes authenticated original evidence.
- Review expected outputs too. They can contain the same sensitive values as inputs.
- Review `git diff --cached` and the complete branch diff before publication. Run `npm run privacy -- --staged`. Heuristics do not certify privacy: names, amounts and uncommon identifiers may evade them.
- Publish only minimum code, fixtures and structured reports. No original bank screenshots or transcript attachments.

For accidental exposure: stop sharing, revoke exposed credentials through the account owner, contact the maintainer privately and follow host removal procedures. Never repeat the secret in an issue.

The landing page accepts no bank uploads and runs only a synthetic example. Hosting providers can receive ordinary access metadata; no analytics or tracking SDK is included.
