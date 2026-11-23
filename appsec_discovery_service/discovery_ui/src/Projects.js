import React, { useState } from 'react';
import {
    List, Datagrid, TextField, FunctionField, TextInput, SelectInput, Button, Link, Show, Title, useRecordContext,
    useDataProvider, useNotify, useRefresh, useListContext, TopToolbar, FilterButton,
} from 'react-admin';
import { useSearchParams } from 'react-router-dom';
import {
    Chip, Dialog, DialogTitle, DialogContent, DialogActions, FormControlLabel, Checkbox, Grid, Stack, Typography,
    Select, MenuItem, FormGroup, Box,
} from '@mui/material';
import {
    jobKindLabel, jobStatusLabel, openQueueFilter, parserChoices, queueCounts, queueFilter, scanModeChoices, severityChoices,
    statusLabel,
} from './choices';
import {
    Ago, AsOf, DetailsSection, GroupPicker, LlmStateChip, Loaded, Panel, ScalePagination, ScanStateChip, SimpleTable,
    StatTile, TagChips, TruncatedNote, fmtDate, fmtNum, listUrl, pluralize, showUrl, useFetch,
} from './common';
import { scopedTitle, useScope } from './scope';

// Projects: one row per GitLab project with its group, open hits, parse state, MRs, LLM coverage, scan mode; the
// project page (GET /projects/{id}); the group view (the projects of a GitLab group with their rollups).

// the group filter is a GitLab path prefix (GET /groups autocomplete)
const GroupFilter = ({ source, label }) => {
    const { filterValues, setFilters, displayedFilters } = useListContext();
    return (
        <GroupPicker value={filterValues[source] || ''} label={label} sx={{ minWidth: 240 }}
                     onChange={v => { const next = { ...filterValues }; if (v) next[source] = v; else delete next[source]; setFilters(next, displayedFilters); }} />
    );
};

const filters = [
    <TextInput source="q" label="Project" alwaysOn />,
    <GroupFilter source="group" label="Group" alwaysOn />,
    <SelectInput source="scan_mode" label="Scan mode" choices={scanModeChoices} />,
    <SelectInput source="severity" label="Project criticality" choices={severityChoices} />,
    <TextInput source="tag" label="Tag" />,
    <SelectInput source="source" label="Source" choices={[{ id: 'gitlab', name: 'GitLab' }, { id: 'external', name: 'Pushed (external)' }]} />,
];

const OPTIONS = [
    ['mains', 'Main branches'],
    ['mrs', 'Open merge requests'],
    ['llm', 'Also run the LLM rules'],
    ['force', 'Force even when unchanged'],
];

// Parse projects again (POST /projects/parse): all, the selected ones or one; optionally some parsers only.
const ParseDialog = ({ open, onClose, projectIds, title, count }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const [busy, setBusy] = useState(false);
    const [opts, setOpts] = useState({ mains: true, mrs: true, llm: false, force: false });
    const [onlySome, setOnlySome] = useState(false);
    const [parsers, setParsers] = useState([]);

    const toggleParser = name => setParsers(parsers.includes(name) ? parsers.filter(p => p !== name) : [...parsers, name]);
    const submit = () => {
        const data = { ...opts };
        if (projectIds) data.project_ids = projectIds;
        if (onlySome) data.parsers = parsers;
        setBusy(true);
        dataProvider.parse('projects', { data })
            .then(({ data: r }) => {
                const already = r.already_queued.length;
                notify(`${pluralize(r.queued.length, 'parse job')} queued` + (already ? `, ${already} already queued` : ''),
                       { type: 'info' });
                onClose();
            })
            .catch(error => notify(error.message || 'Parse failed', { type: 'error' }))
            .finally(() => setBusy(false));
    };

    return (
        <Dialog open={open} onClose={onClose} onClick={e => e.stopPropagation()} fullWidth maxWidth="sm"
                aria-labelledby="parse-title">
            <DialogTitle id="parse-title">{title}</DialogTitle>
            <DialogContent>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                    Main branches are skipped when nothing changed since the last parse with the same rules and parsers
                    (use Force). Without the LLM option, run the LLM rules later from LLM rules ▸ Run.
                    {count !== undefined && count !== null && ` This queues about ${pluralize(count, 'job')} per selected branch kind.`}
                </Typography>
                {OPTIONS.map(([key, label]) => (
                    <FormControlLabel key={key} label={label} control={
                        <Checkbox checked={opts[key]} onChange={e => setOpts({ ...opts, [key]: e.target.checked })} />
                    } />
                ))}
                <FormControlLabel label="Only some parsers (their objects are replaced, the others are kept)" control={
                    <Checkbox checked={onlySome} onChange={e => setOnlySome(e.target.checked)} />
                } />
                {onlySome && (
                    <Box sx={{ pl: 4 }}>
                        <FormGroup row>
                            {parserChoices.map(name => (
                                <FormControlLabel key={name} label={name} control={
                                    <Checkbox size="small" checked={parsers.includes(name)} onChange={() => toggleParser(name)} />
                                } />
                            ))}
                        </FormGroup>
                    </Box>
                )}
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                <Button label="Queue parse" onClick={submit}
                        disabled={busy || !(opts.mains || opts.mrs) || (onlySome && !parsers.length)} />
            </DialogActions>
        </Dialog>
    );
};

const ParseButton = ({ label = 'Parse' }) => {
    const record = useRecordContext();
    const [open, setOpen] = useState(false);
    if (!record) return null;
    return (
        <>
            <Button label={label} onClick={e => { e.stopPropagation(); setOpen(true); }} />
            {open && <ParseDialog open onClose={() => setOpen(false)} projectIds={[record.id]}
                                  title={`Parse ${record.full_path}`} />}
        </>
    );
};

const BulkParseButton = () => {
    const { selectedIds } = useListContext();
    const [open, setOpen] = useState(false);
    return (
        <>
            <Button label="Parse selected" onClick={() => setOpen(true)} />
            {open && <ParseDialog open onClose={() => setOpen(false)} projectIds={selectedIds}
                                  title={`Parse ${pluralize(selectedIds.length, 'project')}`} />}
        </>
    );
};

// every project (the API ignores the list filters here: say how many that is)
const ParseAllButton = () => {
    const { total } = useListContext();
    const [open, setOpen] = useState(false);
    return (
        <>
            <Button label="Parse all" onClick={() => setOpen(true)} />
            {open && <ParseDialog open onClose={() => setOpen(false)} projectIds={null} count={total}
                                  title="Parse every project (not only the filtered ones)" />}
        </>
    );
};

const ListActions = () => (
    <TopToolbar>
        <FilterButton />
        <ParseAllButton />
    </TopToolbar>
);

// rules <-> inventory; the API parses the project again after a switch
const ScanModeSelect = () => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    if (!record) return null;
    const change = e => {
        const scanMode = e.target.value;
        if (scanMode === 'inventory' && !window.confirm(
            `Switch ${record.full_path} to inventory? Open machine hits of the project are deleted; ` +
            'human decisions and manual labels are kept.')) return;
        dataProvider.setScanMode('projects', { id: record.id, data: { scan_mode: scanMode } })
            .then(({ data }) => {
                const mode = (scanModeChoices.find(c => c.id === data.scan_mode) || {}).name || data.scan_mode;
                notify(`${record.full_path}: ${mode}` +
                       (data.removed_machine_hits ? `, ${pluralize(data.removed_machine_hits, 'machine hit')} removed` : '') +
                       ', parse queued', { type: 'info' });
                refresh();
            })
            .catch(error => notify(error.message || 'Update failed', { type: 'error' }));
    };
    return (
        <Select size="small" value={record.scan_mode || 'rules'} onChange={change} onClick={e => e.stopPropagation()}
                inputProps={{ 'aria-label': `Scan mode of ${record.full_path}` }}>
            {scanModeChoices.map(c => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
        </Select>
    );
};

// "scanned a of b active" from scan_progress.mrs (active_24h: MRs with activity in the last day; else all open)
const mrsText = r => {
    const m = r.scan && r.scan.mrs;
    if (!m || !m.open) return 'no open MR';
    if (m.active_24h !== undefined) {
        if (!m.active_24h) return `no active MR (${m.open} open)`;
        return `scanned ${m.active_scanned || 0} of ${m.active_24h} active${m.active_waiting ? `, ${m.active_waiting} waiting` : ''}`;
    }
    return `scanned ${m.scanned_current} of ${m.open} open` + (m.queued + m.running ? `, ${m.queued + m.running} queued` : '');
};

const OpenHits = () => {
    const record = useRecordContext();
    if (!record) return null;
    return record.pending_hits
        ? <Link to={listUrl('hits', openQueueFilter({ project_id: record.id, view: 'list' }))} onClick={e => e.stopPropagation()}>{fmtNum(record.pending_hits)}</Link>
        : <span>0</span>;
};

const GroupLink = () => {
    const record = useRecordContext();
    if (!record || !record.group_path) return null;
    return <Link to={`/groups?path=${encodeURIComponent(record.group_path)}`} onClick={e => e.stopPropagation()}>{record.group_path}</Link>;
};

const ProjectName = () => {
    const record = useRecordContext();
    if (!record) return null;
    return <Link to={showUrl('projects', record.id)}>{record.full_path}</Link>;
};

export const ProjectList = () => {
    const { scope } = useScope();
    return (
        <List filters={filters} actions={<ListActions />} sort={{ field: 'full_path', order: 'ASC' }} perPage={50}
              pagination={<ScalePagination />} title={scopedTitle('Projects', scope)}>
            <Datagrid bulkActionButtons={<BulkParseButton />} rowClick="show">
                <ProjectName label="Project" sortBy="full_path" />
                <GroupLink label="Group" sortable={false} />
                <OpenHits label="Open hits" sortBy="pending_hits" />
                <FunctionField label="Parse" render={r => <ScanStateChip scan={r.scan} />} />
                <FunctionField label="MRs" render={mrsText} />
                <FunctionField label="LLM rules" render={r => <LlmStateChip llm={r.llm} />} />
                <FunctionField label="Criticality" render={r => r.severity || '-'} />
                <ScanModeSelect label="Scan mode" sortBy="scan_mode" />
                <ParseButton />
            </Datagrid>
        </List>
    );
};

// ---- project page (GET /projects/{id}) ------------------------------------------------------------------------------

const ProjectTitle = () => {
    const p = useRecordContext();
    return <span>{p ? p.full_path : 'Project'}</span>;
};

const ProjectActions = () => {
    const p = useRecordContext();
    if (!p) return null;
    return (
        <TopToolbar>
            <Button label="Review hits" component={Link} to={listUrl('hits', openQueueFilter({ project_id: p.id }))} />
            <Button label="Objects" component={Link} to={listUrl('objects', { project_id: p.id })} />
            <Button label="Jobs" component={Link} to={listUrl('jobs', { project_id: p.id })} />
            <ParseButton label="Parse…" />
        </TopToolbar>
    );
};

const hitsLink = (p, extra) => listUrl('hits', { project_id: p.id, presence: 'all', view: 'list', ...extra });

const ProjectBody = () => {
    const p = useRecordContext();
    if (!p) return null;
    const scan = p.scan || {};
    const llm = p.llm || {};
    const byRule = p.hits_by_rule || [];
    const totals = byRule.reduce((t, r) => ({ match: t.match + (r.match || 0), open: t.open + (r.open || 0), questions: t.questions + (r.questions || 0) }),
        { match: 0, open: 0, questions: 0 });
    return (
        <Box p={2}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
                {p.group_path && <Typography variant="body2">Group <Link to={`/groups?path=${encodeURIComponent(p.group_path)}`}>{p.group_path}</Link></Typography>}
                {p.severity && <Chip size="small" variant="outlined" label={`criticality: ${p.severity}`} />}
                {p.visibility && <Chip size="small" variant="outlined" label={p.visibility} />}
                {p.default_branch && <Chip size="small" variant="outlined" label={`default branch ${p.default_branch}`} />}
                {p.source && p.source !== 'gitlab' && <Chip size="small" variant="outlined" label={`source: ${p.source}`} />}
                <TagChips tags={p.tags} />
                <Box flex={1} />
                <Typography variant="body2" color="text.secondary">Scan mode:</Typography>
                <ScanModeSelect />
            </Stack>
            {p.description && <Typography variant="body2" color="text.secondary" gutterBottom>{p.description}</Typography>}
            <Box sx={{ display: 'grid', gap: 2, mb: 2, gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(5, 1fr)' } }}>
                <StatTile title="Parse" level={scan.state === 'failed' ? 'error' : (scan.job ? 'info' : 'ok')}
                          value={<ScanStateChip scan={scan} />}
                          sub1={scan.last_scan_at ? `last parse ${fmtDate(scan.last_scan_at)}` : (p.processed_at ? `synced ${fmtDate(p.processed_at)}` : 'never parsed')}
                          sub2={mrsText(p)} />
                <StatTile title="LLM rules" level={llm.state === 'failed' ? 'error' : (llm.job ? 'info' : 'ok')}
                          value={<LlmStateChip llm={llm} />}
                          sub1={llm.total !== undefined && llm.total !== null ? `${fmtNum(llm.answered)} of ${fmtNum(llm.total)} objects judged` : 'not counted'}
                          sub2={llm.pending_external ? `${llm.pending_external} held by a harness run` : null} />
                <StatTile title="Open hits" level={totals.questions ? 'warning' : (totals.open ? 'info' : 'ok')}
                          value={fmtNum(p.pending_hits ?? totals.open)} sub1={`${pluralize(totals.questions, 'question')} of the harness model`}
                          sub2={`${fmtNum(totals.match)} matches`} to={listUrl('hits', openQueueFilter({ project_id: p.id }))} linkLabel="Review" />
                <StatTile title="Open MRs" level="ok" value={fmtNum(p.open_mrs)}
                          sub1={`${fmtNum(p.objects_in_open_mrs)} objects only in open MRs`} sub2="MRs are markers, not a page"
                          to={listUrl('objects', { project_id: p.id, presence: 'mr' })} linkLabel="Objects only in MRs" />
                <StatTile title="Objects (main)" level="ok" value={fmtNum((p.objects_by_type || []).reduce((n, r) => n + (r.n || 0), 0))}
                          sub1={(p.objects_by_type || []).slice(0, 4).map(r => `${r.type} ${fmtNum(r.n)}`).join(' · ') || 'none'}
                          to={listUrl('objects', { project_id: p.id })} linkLabel="Objects" />
            </Box>
            <Grid container spacing={2}>
                <Panel title="Hits by rule (live hits)" md={7}>
                    <SimpleTable rows={byRule} rowKey={r => r.rule_id} empty="No hit in this project" columns={[
                        { label: 'Rule', render: r => <Link to={r.kind === 'llm' ? `/llm_rules/${r.rule_id}` : (r.kind === 'keyword' ? `/keyword_rules/${r.rule_id}` : hitsLink(p, { rule_id: r.rule_id }))}>{r.rule_name}</Link> },
                        { label: 'Category', render: r => r.category || '-' },
                        { label: statusLabel('match'), render: r => (r.match ? <Link to={hitsLink(p, { rule_id: r.rule_id, status: 'match' })}>{fmtNum(r.match)}</Link> : 0) },
                        { label: statusLabel('no_match'), render: r => (r.no_match ? <Link to={hitsLink(p, { rule_id: r.rule_id, status: 'no_match' })}>{fmtNum(r.no_match)}</Link> : 0) },
                        { label: 'Open', render: r => (r.open ? <Link to={listUrl('hits', openQueueFilter({ project_id: p.id, rule_id: r.rule_id, view: 'list' }))}>{fmtNum(r.open)}</Link> : 0) },
                        { label: 'Questions', render: r => (r.questions ? <Link to={listUrl('hits', queueFilter('questions', { project_id: p.id, rule_id: r.rule_id }))}>{fmtNum(r.questions)}</Link> : 0) },
                    ]} />
                </Panel>
                <Panel title="Objects by type (main branch)" md={5}>
                    <SimpleTable rows={p.objects_by_type || []} rowKey={r => r.type || '-'} empty="No object parsed" columns={[
                        { label: 'Type', render: r => <Link to={listUrl('objects', { project_id: p.id, type: r.type })}>{r.type || '-'}</Link> },
                        { label: 'Objects', render: r => fmtNum(r.n) },
                    ]} />
                    <Typography variant="caption" color="text.secondary" component="div" sx={{ mt: 1 }}>
                        Only in open MRs: <Link to={listUrl('objects', { project_id: p.id, presence: 'mr' })}>{fmtNum(p.objects_in_open_mrs)}</Link>
                        {' · '}open MRs: {fmtNum(p.open_mrs)}
                    </Typography>
                </Panel>
                <Grid item xs={12}>
                    <DetailsSection title="Jobs of this project" count={`last ${(p.jobs || []).length}`} defaultOpen>
                        <SimpleTable rows={p.jobs || []} rowKey={j => j.id} empty="No job for this project yet" columns={[
                            { label: 'Job', render: j => <Link to={showUrl('jobs', j.id)}>#{j.id}</Link> },
                            { label: 'Kind', render: j => jobKindLabel(j.kind) },
                            { label: 'Status', render: j => <Chip size="small" variant="outlined" label={jobStatusLabel(j.status)} color={j.status === 'failed' ? 'error' : (j.status === 'running' ? 'info' : 'default')} /> },
                            { label: 'Subject', render: j => (j.subject ? [j.subject.mr_iid ? `!${j.subject.mr_iid}` : j.subject.branch_name, (j.subject.rule_names || []).join(', ')].filter(Boolean).join(' · ') : '-') },
                            { label: 'Created', render: j => <Ago value={j.created_at} /> },
                            { label: 'Finished', render: j => (j.finished_at ? <Ago value={j.finished_at} /> : '-') },
                            { label: 'Error', render: j => j.last_error || '' },
                        ]} />
                        <Typography variant="caption" color="text.secondary">
                            <Link to={listUrl('jobs', { project_id: p.id })}>All jobs of this project</Link>
                        </Typography>
                    </DetailsSection>
                </Grid>
            </Grid>
        </Box>
    );
};

export const ProjectShow = () => (
    <Show title={<ProjectTitle />} actions={<ProjectActions />}>
        <ProjectBody />
    </Show>
);

// ---- group view (/groups?path=grp/payments) ----------------------------------------------------------------------------

// open hits of a 2-level group key (GET /hits/aggregate by=group) summed under a path
const openUnder = (rows, path) => {
    const hit = rows.filter(r => r.group === path || (r.group || '').startsWith(`${path}/`) || (!path && r.group));
    return hit.length ? hit.reduce((n, r) => n + (Number(r.n) || 0), 0) : null;
};

// The projects of a GitLab group with their rollups: sub-groups (projects, open hits), the open queues of the group
// (one GET /hits/aggregate) and the project list filtered to the group (parse / LLM states per row).
export const GroupView = () => {
    const dataProvider = useDataProvider();
    const [params, setParams] = useSearchParams();
    const { scope, setScope } = useScope();
    const path = (params.get('path') !== null ? params.get('path') : scope) || '';
    const depth = path ? path.split('/').length + 1 : 1;
    const subgroups = useFetch(() => dataProvider.groups({ parent: path || null, depth, limit: 500 }), [path]);
    const queues = useFetch(() => dataProvider.hitsAggregate({ by: ['queue'], filter: { ...(path ? { group: path } : {}), field_marks: false } }), [path]);
    const byGroup = useFetch(() => dataProvider.hitsAggregate({ by: ['group'], filter: { ...openQueueFilter(), ...(path ? { group: path } : {}) } })
        .catch(() => ({ data: { rows: [] } })), [path]);
    const go = p => setParams(prev => { const next = new URLSearchParams(prev); if (p) next.set('path', p); else next.delete('path'); return next; });
    const parent = path.includes('/') ? path.split('/').slice(0, -1).join('/') : '';
    const q = queues.data ? queueCounts(queues.data.rows) : null;
    const groupRows = (byGroup.data && byGroup.data.rows) || [];
    const projects = subgroups.data ? subgroups.data.items.reduce((n, g) => n + (g.projects || 0), 0) : null;
    return (
        <Box p={2}>
            <Title title={path ? `Group ${path}` : 'Groups'} />
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
                <Typography variant="h5">{path ? `Group ${path}` : 'All groups'}</Typography>
                {path && <Button label={parent ? `Up to ${parent}` : 'All groups'} onClick={() => go(parent)} />}
                {path && path !== scope && <Button label="Use as scope" onClick={() => setScope(path)} />}
                {path && path === scope && <Chip size="small" variant="outlined" label="current scope" />}
                <Box flex={1} />
                {queues.data && <AsOf value={queues.data.computed_at} snapshot={queues.data.snapshot} />}
            </Stack>
            <Box sx={{ display: 'grid', gap: 2, mb: 2, gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(5, 1fr)' } }}>
                <StatTile title="Sub-groups" value={subgroups.data ? fmtNum(subgroups.data.items.length) : '…'}
                          sub1={projects !== null ? `${pluralize(projects, 'project')} below` : null} />
                <StatTile title="Questions" level={q && q.questions ? 'warning' : 'ok'} value={q ? fmtNum(q.questions) : '…'}
                          sub1="from the harness model" to={listUrl('hits', queueFilter('questions', path ? { group: path } : {}))} linkLabel="Answer" />
                <StatTile title="Pending review" level={q && q.pending ? 'warning' : 'ok'} value={q ? fmtNum(q.pending) : '…'}
                          sub1="hits of review-mode rules" to={listUrl('hits', queueFilter('pending', path ? { group: path } : {}))} linkLabel="Clusters" />
                <StatTile title="Model unsure" level={q && q.unsure ? 'info' : 'ok'} value={q ? fmtNum(q.unsure) : '…'}
                          sub1="the harness model checks them" to={listUrl('hits', queueFilter('unsure', path ? { group: path } : {}))} linkLabel="Clusters" />
                <StatTile title="Open hits" level="ok" value={q ? fmtNum(q.open) : '…'} sub1="questions + pending + unsure"
                          to={listUrl('hits', openQueueFilter(path ? { group: path } : {}))} linkLabel="Review" />
            </Box>
            <Grid container spacing={2}>
                <Panel title={path ? `Sub-groups of ${path}` : 'Top-level groups'} md={12}>
                    <Loaded state={subgroups}>
                        {d => (
                            <>
                                <SimpleTable rows={d.items} rowKey={g => g.path} empty={path ? 'No sub-group: the projects are listed below' : 'No project synced yet'} columns={[
                                    { label: 'Group', render: g => <Link to={`/groups?path=${encodeURIComponent(g.path)}`}>{g.path}</Link> },
                                    { label: 'Projects', render: g => fmtNum(g.projects) },
                                    { label: 'Open hits', render: g => { const n = openUnder(groupRows, g.path); return n === null ? <span title="counted per 2-level group">-</span> : <Link to={listUrl('hits', openQueueFilter({ group: g.path }))}>{fmtNum(n)}</Link>; } },
                                    { label: '', render: g => <Button size="small" label="Projects" component={Link} to={listUrl('projects', { group: g.path })} /> },
                                ]} />
                                <TruncatedNote shown={d.items.length} total={null} truncated={d.items.length >= 500} what="groups" />
                            </>
                        )}
                    </Loaded>
                </Panel>
                <Grid item xs={12}>
                    <Typography variant="subtitle1" gutterBottom>{path ? `Projects of ${path}` : 'All projects'}</Typography>
                    <List resource="projects" filter={path ? { group: path } : {}} filters={filters.filter(f => f.props.source !== 'group')}
                          sort={{ field: 'pending_hits', order: 'DESC' }} perPage={25} pagination={<ScalePagination />}
                          disableSyncWithLocation actions={false} title=" " storeKey={`groups.projects.${path}`}>
                        <Datagrid bulkActionButtons={<BulkParseButton />} rowClick="show">
                            <ProjectName label="Project" sortBy="full_path" />
                            <OpenHits label="Open hits" sortBy="pending_hits" />
                            <FunctionField label="Parse" render={r => <ScanStateChip scan={r.scan} />} />
                            <FunctionField label="MRs" render={mrsText} />
                            <FunctionField label="LLM rules" render={r => <LlmStateChip llm={r.llm} />} />
                            <FunctionField label="Criticality" render={r => r.severity || '-'} />
                            <TextField source="scan_mode" label="Scan mode" />
                        </Datagrid>
                    </List>
                </Grid>
            </Grid>
        </Box>
    );
};
