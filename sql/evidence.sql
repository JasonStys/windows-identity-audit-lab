-- Jason Stys: bounded review metadata and SID findings, not credential material or personal names.
-- BEGIN CODE MAP (generated; python scripts/code_map.py)
-- SQL object: review — line 18
-- column: as_of — line 18
-- column: captured — line 18
-- column: complete — line 18
-- column: host — line 18
-- SQL object: finding — line 19
-- column: action — line 19
-- column: detail — line 19
-- column: path — line 19
-- column: rule — line 19
-- column: severity — line 19
-- column: subject — line 19
-- SQL object: finding_subject — line 20
-- END CODE MAP
PRAGMA foreign_keys = ON;
CREATE TABLE review (host TEXT NOT NULL, captured TEXT NOT NULL, as_of TEXT NOT NULL, complete INTEGER NOT NULL CHECK(complete IN (0,1)));
CREATE TABLE finding (rule TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('high','medium','review')), subject TEXT NOT NULL, path TEXT NOT NULL, detail TEXT NOT NULL, action TEXT NOT NULL);
CREATE INDEX finding_subject ON finding(subject);
