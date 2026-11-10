# Windows Identity Audit Lab handbook

By Jason Stys.

Review nested protected-identity exposure, representative paths, source completeness and owner recertification/expiry queues.

Keeps complete exposure separate from newly observed drift and avoids false removal claims from partial snapshots.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions, and the workbook is an evidence index rather than a test runner. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [review](review.md)
- [runbook](runbook.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [performance](performance.md)
- [security](security.md)
- [testing](testing.md)
- [validation](validation.md)

## Historical results and reproduction

The reviewed source is [`b82073c8ae41450b917ec7b3dde9eca40d7d30ea`](https://github.com/JasonStys/windows-identity-audit-lab/tree/b82073c8ae41450b917ec7b3dde9eca40d7d30ea). The observed functional workflow baseline is `b82073c8ae41450b917ec7b3dde9eca40d7d30ea`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/recertification-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/windows-identity-audit-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- SID evidence can be identifying private plaintext; it does not prove effective access or successful revocation.
- Exposure reports show one shortest representative path, not every possible nested path.
- Absence in partial, unresolved or cyclic evidence is unverified; recertification is not automatically renewed.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.
