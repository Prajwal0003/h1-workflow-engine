# License scope and third-party material

Prajwal Sankpal licenses his original H1 Workflow Engine code and documentation under the [MIT License](LICENSE). The grant applies only to work he owns. Upstream code, binaries, rules, wordlists, datasets, reports and third-party contributions retain their respective rights.

| Material | Status |
| --- | --- |
| Bundled ffuf, gau and nuclei distributions | Keep the notices shipped in [ffuf](tools/ffuf/LICENSE), [gau](tools/gau/LICENSE) and [nuclei](tools/nuclei/LICENSE.md) with their distributions. |
| `scanners/mantishack_features/` and the `ext/mantishack` Git reference | The Git reference identifies [Mantishack revision 15f8c8b](https://github.com/deonmenezes/mantishack/tree/15f8c8ba1652f9eef81be80470930fc7d0b3f581). The imported directory includes the [RAPTOR license](scanners/mantishack_features/LICENSE), [Mantishack license](scanners/mantishack_features/LICENSE-MANTISHACK) and [upstream notice](scanners/mantishack_features/NOTICE) from that revision. Embedded rules, datasets and integrations may have separate terms. The copied tree is a subset and may contain local changes. |
| Other bundled executables, wordlists, external templates and datasets | Check upstream provenance and terms individually before redistributing. The project MIT grant does not cover them. |

A release that redistributes bundled components needs a component inventory with source, version, copyright notice, license and applicable distribution obligations for every included third-party item. Components with unresolved permissions should be left out of the release.
