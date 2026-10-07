# CyberIntel compatibility migration plan

No removal happens in this release. Source installations retain cyberintel-suite
0.1.0, cyberintel and cyberrecon entry points and independent workspaces.
CyberRecon 0.2.0 requires five CyberIntel shared modules: models, output,
connectors, nmap_scan and web_assessment, plus the initializer. The Debian package
ships this subset; it does not ship the legacy GUI. Keep this boundary explicit.

A future separately reviewed change should first inventory callers and tests,
move shared primitives into a neutral internal package with compatibility imports,
then qualify both applications and data paths before deprecation. Preserve old
imports/entry points through a documented transition period. Any distribution
rename/version alignment needs an explicit release note, dependency and upgrade
plan. Never silently migrate or merge legacy user databases; add opt-in backed-up
migration with rollback tests if needed. Removal requires explicit authorization
and a later major/deprecation decision after consumers have migrated.
