# Active Context


## Facts
- **Microsoft Active Directory (AD)**: Contains user and group details and allows an Identity Provider (IdP) to perform authentication.
- User's PC has a web browser to access web applications, which is essential for SAML and OIDC authentication flows that rely on browser redirects.
- Users access Internet applications or SaaS through an outgoing proxy that blocks blacklisted websites based on threat intelligence, enhancing security for external communications.

## Current Work Focus
- Establishing the Memory Bank structure for the Architect Library project.
- Documenting core project information to ensure continuity across sessions.

## Recent Changes
- Created foundational Memory Bank files including 'projectbrief.md' and 'productContext.md'.
- Setting up documentation workflows to maintain project context.
- Updated 'design_patterns/security/sso.md' to reflect network architecture: no firewall between user and internal web applications (trusted internal zone), and a firewall between user PC and SaaS on the Internet (boundary between trusted internal and untrusted Internet zones).
- Further updated 'design_patterns/security/sso.md' to include firewalls between user and web application, and between IdP and web application for micro-segmentation within the internal network.

## Next Steps
- Complete the creation of remaining core Memory Bank files.
- Begin documenting specific architectural patterns and security practices.
- Establish a process for updating Memory Bank files after significant project changes.

## Active Decisions and Considerations
- How to structure additional context files for complex features and integrations.
- Determining the frequency and triggers for Memory Bank updates.

## Important Patterns and Preferences
- Use Markdown for all documentation to ensure readability and ease of updates.
- Maintain a clear hierarchy in documentation to reflect project structure and priorities.
- Avoid using colons and periods in Mermaid diagram descriptions to prevent "Unsupported markdown: list" errors; use hyphens or other separators instead.

## Learnings and Project Insights
- Consistent documentation is critical for project continuity given memory resets.
- A well-structured Memory Bank facilitates quick onboarding and context recovery.
