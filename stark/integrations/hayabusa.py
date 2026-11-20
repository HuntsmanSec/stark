"""Hayabusa (https://github.com/Yamato-Security/hayabusa) integration.

Typical workflow::

    hayabusa csv-timeline -d ./evtx -o timeline.csv -p verbose
    stark enrich timeline.csv --preset hayabusa -o timeline.stark.csv --stix iocs.stix.json

Hayabusa puts the interesting event data in ``Details`` (and ``ExtraFieldInfo``
for the ``verbose``/``all-field-info`` profiles); with JSON output the same keys
hold nested objects. STARK strips ``IMPHASH=`` values so they are not mistaken
for MD5 hashes.
"""

EVIDENCE_COLUMNS = ["Details", "ExtraFieldInfo", "AllFieldInfo", "Event"]
SKIP_COLUMNS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID",
                "RuleFile", "EvtxFile", "MitreTactics", "MitreTags", "OtherTags", "Provider",
                "RuleAuthor", "RuleCreationDate", "RuleModifiedDate", "Status", "RuleID"]
