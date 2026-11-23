-- Synthetic inventory for plan checks (adapted from the storage design benchmark):
-- :projects projects x 600 objects x 8 fields on main, 2 open MRs per project with
-- 15 modified objects (9 new passport fields each) + 1 removed, 10 merged MRs per project.
INSERT INTO gitlab_projects (gitlab_id, project_name, full_path, visibility, created_at, updated_at)
  SELECT g, 'p' || g, 'grp/p' || g, 'private', now(), now() FROM generate_series(1, :projects) g;
INSERT INTO gitlab_branches (project_id, branch_name, is_main, commit, project_path, created_at, updated_at)
  SELECT id, 'main', true, 'c', full_path, now(), now() FROM gitlab_projects;
INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file, props)
  SELECT md5('c' || p || '-' || o)::uuid, md5('k' || p || '-' || o)::uuid, p, 'go', 'dto', 'Obj' || o, 'f' || (o % 50) || '.go', '{}'
  FROM generate_series(1, :projects) p, generate_series(1, 600) o;
INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id)
  SELECT o.content_hash,
    (ARRAY['id','name','email','passport_number','card_pan','phone','created_at','amount','token','address'])[1 + ((f + abs(hashtext(o.name))) % 10)] || f,
    'string', md5(o.object_key::text || f)::uuid, o.project_id
  FROM objects o, generate_series(1, 8) f;
INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, line)
  SELECT b.id, o.object_key, o.content_hash, true, 10
  FROM objects o JOIN gitlab_branches b ON b.project_id = o.project_id AND b.is_main;
INSERT INTO gitlab_branches (project_id, branch_name, is_main, commit, project_path, created_at, updated_at)
  SELECT p, 'feat-' || m, false, 'c', 'grp/p' || p, now(), now() FROM generate_series(1, :projects) p, generate_series(1, 2) m;
INSERT INTO gitlab_mrs (project_id, project_path, mr_id, state, source_branch_id, source_branch, source_branch_commit,
                        target_branch_id, target_branch, target_branch_commit, title, created_at, updated_at)
  SELECT b.project_id, b.project_path, row_number() OVER (PARTITION BY b.project_id), 'opened', b.id, b.branch_name, 'c',
         mb.id, 'main', 'c', 't', now(), now()
  FROM gitlab_branches b JOIN gitlab_branches mb ON mb.project_id = b.project_id AND mb.is_main WHERE NOT b.is_main;
INSERT INTO gitlab_mrs (project_id, project_path, mr_id, state, source_branch, source_branch_commit, target_branch,
                        target_branch_commit, title, created_at, updated_at, closed_at)
  SELECT p, 'grp/p' || p, 100 + m, 'merged', 'x', 'c', 'main', 'c', 't', now(), now(), now()
  FROM generate_series(1, :projects) p, generate_series(1, 10) m;
INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file, props)
  SELECT md5('mr' || b.id || '-' || o)::uuid, md5('k' || b.project_id || '-' || o)::uuid, b.project_id, 'go', 'dto', 'Obj' || o, 'x.go', '{}'
  FROM gitlab_branches b, generate_series(1, 15) o WHERE NOT b.is_main;
INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id)
  SELECT o.content_hash, 'passport_series' || f, 'string', md5(o.object_key::text || 'ps' || f)::uuid, o.project_id
  FROM objects o, generate_series(1, 9) f WHERE o.file = 'x.go';
INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, change, line)
  SELECT b.id, md5('k' || b.project_id || '-' || o)::uuid, md5('mr' || b.id || '-' || o)::uuid, false, 'modified', 5
  FROM gitlab_branches b, generate_series(1, 15) o WHERE NOT b.is_main;
INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, change)
  SELECT b.id, md5('k' || b.project_id || '-599')::uuid, NULL, false, 'removed' FROM gitlab_branches b WHERE NOT b.is_main;
INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, category, severity, status, first_seen_at, last_seen_at)
  SELECT (SELECT id FROM rules WHERE name = 'llm'), f.field_key, f.project_id, o.object_key, f.field_name, 1, 'pii', 'high',
         (ARRAY['match','pending_review','no_match'])[1 + (abs(hashtext(f.field_name || f.project_id)) % 3)], now(), now()
  FROM object_fields f JOIN objects o USING (content_hash)
  WHERE f.field_name LIKE 'passport%' OR f.field_name LIKE 'card%'
  ON CONFLICT DO NOTHING;
