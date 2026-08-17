-- GH Archive (BigQuery public dataset) -> the credibility capstone:
-- a real count of home-server-identity commits + a growth curve over time, with the
-- co-author-trailer leak counted separately from the author-email leak.
--
-- NOTE: do NOT use `githubarchive.day.*` (wildcard). That dataset mixes VIEWS
-- (yesterday/today/this_month) in with the date tables and the wildcard errors:
-- "Views cannot be queried through prefix." Reference explicit day tables with UNION ALL.
--
-- COST: only `type` + `payload` columns are scanned across 15 day-tables (~tens of GB total),
-- inside the 1 TB/month free tier / BigQuery Sandbox. Check the estimate before running.
--
-- pushes_lan_author   = PushEvents whose payload has a commit author email @<host>.local/.lan/.home
-- pushes_lan_coauthor = PushEvents whose payload has a `Co-authored-by:` trailer with such an email
--                       (this is the ~93% that author-field-only audits miss)

SELECT * FROM (
  SELECT '20230115' AS day, COUNT(*) AS push_events,
    COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')) AS pushes_lan_author,
    COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) AS pushes_lan_coauthor
  FROM `githubarchive.day.20230115` WHERE type='PushEvent'
  UNION ALL SELECT '20230415', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20230415` WHERE type='PushEvent'
  UNION ALL SELECT '20230715', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20230715` WHERE type='PushEvent'
  UNION ALL SELECT '20231015', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20231015` WHERE type='PushEvent'
  UNION ALL SELECT '20240115', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20240115` WHERE type='PushEvent'
  UNION ALL SELECT '20240415', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20240415` WHERE type='PushEvent'
  UNION ALL SELECT '20240715', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20240715` WHERE type='PushEvent'
  UNION ALL SELECT '20241015', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20241015` WHERE type='PushEvent'
  UNION ALL SELECT '20250115', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20250115` WHERE type='PushEvent'
  UNION ALL SELECT '20250415', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20250415` WHERE type='PushEvent'
  UNION ALL SELECT '20250715', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20250715` WHERE type='PushEvent'
  UNION ALL SELECT '20251015', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20251015` WHERE type='PushEvent'
  UNION ALL SELECT '20260115', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20260115` WHERE type='PushEvent'
  UNION ALL SELECT '20260415', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20260415` WHERE type='PushEvent'
  UNION ALL SELECT '20260715', COUNT(*), COUNTIF(REGEXP_CONTAINS(payload, r'"email":"[^"]+@[a-z0-9-]+\.(?:local|lan|home)"')), COUNTIF(REGEXP_CONTAINS(payload, r"(?i)co-authored-by:.{0,120}?@[a-z0-9.-]+\.(?:local|lan|home)")) FROM `githubarchive.day.20260715` WHERE type='PushEvent'
) ORDER BY day;
