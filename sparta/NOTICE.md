# SPARTA notice

`sparta/data/index.json` is derived from the SPARTA STIX 2.1 dataset
(version v3.2), downloaded from https://sparta.aerospace.org/resources/working-with.
It keeps each technique's ID, name, and tactic, plus the IDs of related SPARTA
countermeasures and the names of SPARTA indicators.

The Aerospace Corporation. This work is reproduced and distributed with the
permission of The Aerospace Corporation.

SPARTA Terms of Service: https://sparta.aerospace.org/terms-of-service

SPARTA is a registered trademark of The Aerospace Corporation. This project is
not affiliated with or endorsed by The Aerospace Corporation. The MIT license
of this repository does not apply to the SPARTA content in `sparta/data/`.

To rebuild the index from a newer release:

    python -m sparta.build_index path/to/sparta_data.json
