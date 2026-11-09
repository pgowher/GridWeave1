# Mapping from authored profiles to the native export

The six profile definitions are synthetic governance fixtures. Their names motivate a smart-grid lifecycle setting; they are not operational case reports or evidence of realistic population frequencies.

| Source field | Native representation | Meaning retained |
| --- | --- | --- |
| id | scenario_id and case metadata | Authored profile identity |
| asset_kinds | topology assets | One asset node per declared source entry, retaining kind |
| repositories and custodians | topology repositories and custodian principal IDs | Declared repository count and modulo-assigned custodian ownership |
| placements | topology replicas | One replica per asset–repository placement; several placements can refer to one asset |
| edges | directed lineage_edges | Declared parent-to-child derivation, including joins |
| roots | case root_asset_ids | Seeds for reachable obligation scope |
| reachable placements | receipts and reconstructed obligations | A successful receipt for each reachable replica in the default policy |
| profile payload digest | provenance source_bundle_sha256 | Binding to the actual authored profile rather than the inherited exchange template |

The scope commitment includes all declared topology records, including unrelated assets. Default per-replica obligation reconstruction follows reachability from the roots. Thus an unrelated declared asset is represented and committed but does not acquire an obligation merely by being visible.

The common policy has a 48-hour deadline, ERASED as its permitted disposition, signed E2 evidence, no overrides and no early closure. This is a declared fixture policy. It is not a translation of heterogeneous source policy requirements and is not a legal interpretation. The ten existing paired operators supply the controlled assessment changes and invariances.

The generator uses a saved native case as an exchange-envelope template, then replaces the profile, topology, case identifiers, policy, receipts, signing context and provenance binding. Its source snapshot captures the driver, profile file and frozen upstream generation/support files. The native schema fixes producer at PaEGen; resource authorship and version are separately recorded. This compatibility marker is not independent endorsement.

The automated generation and consumer checks test consistency under these declared meanings. Expert review of the profile meanings and independent label adjudication remain outstanding.
