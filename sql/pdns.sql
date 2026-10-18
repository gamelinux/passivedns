-- PassiveDNS table created by tools/pdns2db.py when it is missing.
-- The default name is pdns. PDNS_DB_TABLE may select another identifier.
-- search-pdns.pl and www/index.php read this table.
-- ANSWER is MEDIUMTEXT so a TXT value fits. AHASH is SHA-256 of the
-- stored answer and is the unique key, because a full TXT cannot sit
-- in an index. pdns2db.py widens an older varchar(255) table on its
-- first run. That rewrite needs ALTER and INDEX on the table.

CREATE TABLE IF NOT EXISTS pdns (
    ID         BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    QUERY      varchar(255)        NOT NULL DEFAULT '',
    MAPTYPE    varchar(10)         NOT NULL DEFAULT '',
    RR         varchar(10)         NOT NULL DEFAULT '',
    ANSWER     MEDIUMTEXT          NOT NULL,
    AHASH      BINARY(32)          NOT NULL,
    TTL        int(10)             NOT NULL DEFAULT '0',
    COUNT      BIGINT(20) UNSIGNED NOT NULL DEFAULT '1',
    FIRST_SEEN DATETIME            NOT NULL,
    LAST_SEEN  DATETIME            NOT NULL,
    PRIMARY KEY (ID),
    UNIQUE KEY MARQ (MAPTYPE, AHASH, RR, QUERY),
    KEY query_idx (QUERY),
    KEY answer_idx (ANSWER(255))
);
