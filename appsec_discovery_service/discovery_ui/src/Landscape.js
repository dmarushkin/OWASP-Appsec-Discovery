import React, { useState } from 'react';
import { Link, Title, useDataProvider, useNotify } from 'react-admin';
import {
    Alert, Box, Button, Grid, MenuItem, Stack, Table, TableBody, TableCell, TableHead, TablePagination,
    TableRow, TextField as MuiTextField, Typography,
} from '@mui/material';
import { severityChoices } from './choices';
import {
    AsOf, Loaded, Panel, ProjectPicker, RulePicker, SimpleTable, TruncatedNote, fmtNum, listUrl, showUrl, useCategories, useFetch,
} from './common';
import { scopedTitle, useScope } from './scope';

// Landscape: where in the landscape the data of category X lives. GET /overview with category / tag / rule_id /
// severity / project_id: the summary (matches, objects by type) and `matches_by_project` (the top 200 projects by
// matches - said so); GET /hits/aggregate by group: the matches per GitLab group inside the scope.

const PAGE = 25;
const TYPES = ['table', 'rpc', 'query', 'mutation'];
const PROJECTS_TOP = 200;   // the API's cap of matches_by_project

const matchesOf = overview => (overview.confirmed_by_category || []).reduce((n, r) => n + (r.n || 0), 0);

// search_hits(status=["match"], category="pii", ...) for a harness
const mcpQuery = (f, scope) => {
    const args = ['status=["match"]'];
    if (f.category) args.push(`category="${f.category}"`);
    if (f.tag) args.push(`tag="${f.tag}"`);
    if (f.ruleId) args.push(`rule_id=${f.ruleId}`);
    if (f.severity) args.push(`severity="${f.severity}"`);
    if (f.project) args.push(`project_id=${f.project.id}`);
    if (scope && !f.project) args.push(`group="${scope}"`);
    return `search_hits(${args.join(', ')})`;
};

const csvOf = rows => {
    const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const head = ['project', ...TYPES, 'matches', 'open'];
    const lines = rows.map(r => [r.project_path, ...TYPES.map(t => (r.by_type || {})[t] || 0), r.matches, r.open].map(esc).join(','));
    return [head.join(','), ...lines].join('\n');
};

const download = (name, text) => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
};

const Filters = ({ value, onChange }) => {
    const categories = useCategories();
    const set = patch => onChange({ ...value, ...patch });
    return (
        <Box display="flex" gap={1} alignItems="center" flexWrap="wrap">
            <MuiTextField select label="Category" value={value.category} onChange={e => set({ category: e.target.value })} size="small"
                          margin="dense" sx={{ minWidth: 180 }}>
                <MenuItem value="">(all)</MenuItem>
                {categories.map(c => <MenuItem key={c} value={c}>{c}</MenuItem>)}
            </MuiTextField>
            <MuiTextField label="Tag" value={value.tag} onChange={e => set({ tag: e.target.value })} size="small" margin="dense" />
            <RulePicker value={value.ruleId} onChange={ruleId => set({ ruleId })} />
            <MuiTextField select label="Severity" value={value.severity} onChange={e => set({ severity: e.target.value })} size="small"
                          margin="dense" sx={{ minWidth: 140 }}>
                <MenuItem value="">(all)</MenuItem>
                {severityChoices.map(c => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
            </MuiTextField>
            <Box minWidth={300}><ProjectPicker value={value.project} onChange={project => set({ project })} label="Project (empty: all)" /></Box>
        </Box>
    );
};

const hitsFilter = (f, projectId) => ({
    status: 'match', presence: 'all', view: 'list',
    ...(f.category ? { category: f.category } : {}), ...(f.severity ? { severity: f.severity } : {}),
    ...(f.ruleId ? { rule_id: f.ruleId } : {}), ...(projectId ? { project_id: projectId } : {}),
});

const ByProject = ({ rows, filter }) => {
    const [page, setPage] = useState(0);
    const sorted = [...rows].sort((a, b) => (b.matches || 0) - (a.matches || 0));
    const shown = sorted.slice(page * PAGE, page * PAGE + PAGE);
    return (
        <Box>
            <Table size="small">
                <TableHead>
                    <TableRow>
                        <TableCell>Project</TableCell>
                        {TYPES.map(t => <TableCell key={t} align="right">{{ table: 'Tables', rpc: 'RPC', query: 'Queries', mutation: 'Mutations' }[t]}</TableCell>)}
                        <TableCell align="right">Matches</TableCell>
                        <TableCell align="right">Open</TableCell>
                        <TableCell />
                    </TableRow>
                </TableHead>
                <TableBody>
                    {shown.map(r => (
                        <TableRow key={r.project_id}>
                            <TableCell><Link to={showUrl('projects', r.project_id)}>{r.project_path}</Link></TableCell>
                            {TYPES.map(t => <TableCell key={t} align="right">{fmtNum((r.by_type || {})[t] || 0)}</TableCell>)}
                            <TableCell align="right">{fmtNum(r.matches)}</TableCell>
                            <TableCell align="right">{fmtNum(r.open)}</TableCell>
                            <TableCell>
                                <Link to={listUrl('hits', hitsFilter(filter, r.project_id))}>Hits</Link>
                                {' · '}
                                <Link to={listUrl('objects', { project_id: r.project_id, ...(filter.tag ? { tag: filter.tag } : {}) })}>Objects</Link>
                            </TableCell>
                        </TableRow>
                    ))}
                    {!shown.length && <TableRow><TableCell colSpan={8}><Typography variant="body2" color="text.secondary">No project has a match for these filters.</Typography></TableCell></TableRow>}
                </TableBody>
            </Table>
            {rows.length > PAGE && (
                <TablePagination component="div" count={rows.length} page={page} onPageChange={(e, p) => setPage(p)} rowsPerPage={PAGE}
                                 rowsPerPageOptions={[PAGE]} />
            )}
        </Box>
    );
};

// GET /hits/aggregate by group (2 GitLab path levels) of the matches: where the category lives, group by group (the
// tag filter is an object filter the hits aggregate does not have: it is not applied here)
const ByGroup = ({ filter, scope }) => {
    const dataProvider = useDataProvider();
    const { view, ...hits } = hitsFilter(filter, filter.project ? filter.project.id : null);
    const state = useFetch(() => dataProvider.hitsAggregate({ by: ['group'], filter: hits }), [JSON.stringify(hits), scope]);
    return (
        <Loaded state={state}>
            {d => (
                <>
                    <SimpleTable rows={(d.rows || []).filter(r => r.group)} rowKey={r => r.group} empty="No match in any group for these filters" columns={[
                        { label: 'Group', render: r => <Link to={`/groups?path=${encodeURIComponent(r.group)}`}>{r.group}</Link> },
                        { label: 'Matches', render: r => <Link to={listUrl('hits', { ...hits, group: r.group })}>{fmtNum(r.n)}</Link> },
                        { label: 'Share', render: r => (d.total ? `${Math.round((r.n / d.total) * 100)}%` : '-') },
                    ]} />
                    <TruncatedNote shown={(d.rows || []).length} total={null} truncated={d.truncated} what="groups" />
                    <AsOf value={d.computed_at} snapshot={d.snapshot} />
                </>
            )}
        </Loaded>
    );
};

export const Landscape = () => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const { scope } = useScope();
    const [filter, setFilter] = useState({ category: '', tag: '', ruleId: null, severity: '', project: null });
    const projectId = filter.project ? filter.project.id : null;
    const query = { projectId, category: filter.category || null, tag: filter.tag || null, ruleId: filter.ruleId || null,
        severity: filter.severity || null };
    const state = useFetch(() => dataProvider.overview(query), [projectId, filter.category, filter.tag, filter.severity, filter.ruleId]);
    const copy = () => navigator.clipboard && navigator.clipboard.writeText(mcpQuery(filter, scope))
        .then(() => notify('Copied', { type: 'info' }), () => notify('Copy failed', { type: 'warning' }));
    return (
        <Box p={2}>
            <Title title={scopedTitle('Landscape', scope)} />
            <Box display="flex" alignItems="center" gap={2} mb={1} flexWrap="wrap">
                <Typography variant="h5">Landscape</Typography>
                {scope && (
                    <Typography variant="body2" color="text.secondary">
                        the overview counts the whole landscape; the "By group" panel honours the scope {scope}
                    </Typography>
                )}
                <Box flex={1} />
                <Button size="small" onClick={copy} title={mcpQuery(filter, scope)}>Copy MCP query</Button>
                {state.data && state.data.matches_by_project && (
                    <Button size="small" onClick={() => download('landscape.csv', csvOf(state.data.matches_by_project))}
                            title={`The top ${PROJECTS_TOP} projects by matches (what the API returns)`}>
                        Export CSV ({state.data.matches_by_project.length} projects)
                    </Button>
                )}
            </Box>
            <Filters value={filter} onChange={setFilter} />
            <Loaded state={state}>
                {data => {
                    const rows = data.matches_by_project;
                    const projects = rows ? rows.filter(r => r.matches).length : null;
                    const capped = rows && rows.length >= PROJECTS_TOP;
                    return (
                        <Stack spacing={2} sx={{ mt: 1 }}>
                            <Typography variant="body1" component="div">
                                Matches: <b>{fmtNum(matchesOf(data))}</b>
                                {projects !== null ? <> in <b>{capped ? `${fmtNum(projects)}+` : fmtNum(projects)}</b> projects{capped ? ` (the top ${PROJECTS_TOP} by matches are listed)` : ''}</> : ''}
                                {' · '}
                                <Typography component="span" variant="body2" color="text.secondary">
                                    Objects by type: {(data.objects_by_type || []).map(r => `${r.type} ${fmtNum(r.n)}`).join(' · ') || 'none'}
                                </Typography>
                                {' · '}<AsOf value={data.computed_at} snapshot={data.snapshot} />
                            </Typography>
                            <Grid container spacing={2}>
                                <Panel title="By GitLab group (matches)" md={4}>
                                    <ByGroup filter={filter} scope={scope} />
                                </Panel>
                                <Panel title="By project" md={8}>
                                    {rows ? (
                                        <>
                                            <ByProject rows={rows} filter={filter} />
                                            <TruncatedNote shown={rows.length} total={null} truncated={capped} what="projects"
                                                           hint="the top projects by matches; narrow by category, rule or group for the rest" />
                                        </>
                                    ) : (
                                        <Alert severity="info">Per-project breakdown needs the API update (overview matches_by_project).</Alert>
                                    )}
                                </Panel>
                                <Panel title="Matches by category and severity" md={6}>
                                    <SimpleTable rows={data.confirmed_by_category} rowKey={r => `${r.category}:${r.severity}`} empty="No matches yet" columns={[
                                        { label: 'Category', render: r => <Link to={listUrl('hits', { ...hitsFilter(filter, projectId), category: r.category, severity: r.severity })}>{r.category || '-'}</Link> },
                                        { label: 'Severity', source: 'severity' },
                                        { label: 'Hits', render: r => fmtNum(r.n) },
                                    ]} />
                                    <TruncatedNote shown={(data.confirmed_by_category || []).length} total={null}
                                                   truncated={(data.confirmed_by_category || []).length >= 30} what="category rows" />
                                </Panel>
                                <Panel title="Objects by type (main branches)" md={6}>
                                    <SimpleTable rows={data.objects_by_type} rowKey={r => r.type || '-'} empty="No objects yet" columns={[
                                        { label: 'Type', render: r => <Link to={listUrl('objects', { type: r.type, ...(projectId ? { project_id: projectId } : {}) })}>{r.type}</Link> },
                                        { label: 'Objects', render: r => fmtNum(r.n) },
                                    ]} />
                                </Panel>
                            </Grid>
                        </Stack>
                    );
                }}
            </Loaded>
        </Box>
    );
};
