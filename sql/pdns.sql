-- PassiveDNS table created by tools/pdns2db.pl when it is missing.
-- The default name is pdns. PDNS_DB_TABLE may select another identifier.
-- search-pdns.pl and www/index.php read this table.

CREATE TABLE IF NOT EXISTS pdns (
    ID         BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    QUERY      varchar(255)        NOT NULL DEFAULT '',
    MAPTYPE    varchar(10)         NOT NULL DEFAULT '',
    RR         varchar(10)         NOT NULL DEFAULT '',
    ANSWER     varchar(255)        NOT NULL DEFAULT '',
    TTL        int(10)             NOT NULL DEFAULT '0',
    COUNT      BIGINT(20) UNSIGNED NOT NULL DEFAULT '1',
    FIRST_SEEN DATETIME            NOT NULL,
    LAST_SEEN  DATETIME            NOT NULL,
    PRIMARY KEY (ID),
    UNIQUE KEY MARQ (MAPTYPE, ANSWER, RR, QUERY),
    KEY query_idx (QUERY),
    KEY answer_idx (ANSWER)
);
