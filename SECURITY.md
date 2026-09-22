# Security

Do not use experimental parser results alone to release money. Inputs are unauthenticated. No hosted bank-session processing or signing service exists here.

Report vulnerabilities or exposed data through GitHub private vulnerability reporting on this repository. If unavailable, email 0xsachink@gmail.com with a minimal description, not credentials or raw banking data. Avoid public issues for exploit details or personal records.

CI runs on disposable GitHub-hosted runners, with read-only contents permissions, no repository secrets, no credential persistence, no `pull_request_target`, no self-hosted runners and no live bank sessions. Dependencies install with lifecycle scripts disabled. Dependency updates and workflow changes require review. Public build artifacts contain only the landing page and public catalog.
