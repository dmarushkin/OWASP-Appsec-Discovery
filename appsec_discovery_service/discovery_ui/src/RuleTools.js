import React, { useState } from 'react';
import {
    Button, DeleteButton, FormDataConsumer, Link, SaveButton, Toolbar, useDataProvider, useNotify, useRecordContext,
} from 'react-admin';
import { Box, Card, CardContent, CardHeader, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';
import { Loaded, ProjectPicker, SimpleTable, fmtNum, fmtPct, listUrl, useFetch } from './common';
import { statusLabel } from './choices';

// Shared pieces of the rule forms: the spec the API accepts, the dry run (POST /rules/dry_run), the "Count objects in
// scope" button, the toolbar of the keyword form and the statistics aside (GET /rules/stats).

// what the API accepts in a rule spec (schemas.KeywordRuleIn / LlmRuleIn); the rest of a record is read-only
const RULE_KEYS = {
    keyword: ['name', 'category', 'severity', 'mode', 'enabled', 'action', 'project_re', 'parser', 'object_re',
        'object_type_re', 'field_re', 'field_type_re', 'fields_all', 'fields_none', 'min_groups', 'tags'],
    llm: ['name', 'category', 'severity', 'mode', 'enabled', 'target', 'prompt', 'project_re', 'object_re',
        'object_type_re', 'field_re', 'field_type_re', 'mark_fields', 'tags'],
};

export const ruleSpec = (kind, values) => {
    const spec = {};
    RULE_KEYS[kind].forEach(k => {
        const v = values[k];
        if (Array.isArray(v)) {
            const items = v.filter(x => x && String(x).trim());
            if (items.length) spec[k] = items;
        } else if (v !== undefined && v !== null && v !== '') {
            spec[k] = v;
        }
    });
    // mark_fields only applies to object rules (the API rejects it on a field rule)
    if (kind === 'llm' && spec.target !== 'object') delete spec.mark_fields;
    return spec;
};

const countTable = (counts, label) => (
    <SimpleTable rows={Object.entries(counts || {}).map(([k, n]) => ({ k, n }))} rowKey={r => r.k}
                 columns={[{ label, source: 'k' }, { label: 'Hits', source: 'n' }]} empty="none" />
);

const KeywordResult = ({ r }) => (
    <>
        <Typography gutterBottom>
            <b>{fmtNum(r.hits)}</b> hits on {fmtNum(r.objects_scanned)} objects of {fmtNum(r.projects)} projects
            {r.truncated ? ' (truncated: too many objects, the counts are a lower bound)' : ''}.
            {r.rule_id !== undefined && ` Now: ${fmtNum(r.current_hits)} hits; the saved form would add ${fmtNum(r.new)} and drop ${fmtNum(r.gone)}.`}
        </Typography>
        <Typography gutterBottom>
            Objects / fields a human already decided (any rule): <b>{fmtNum(r.human_confirmed)}</b> matched,{' '}
            <b>{fmtNum(r.human_rejected)}</b> marked no match by a human
            {r.human_rejected > r.human_confirmed ? ' - mostly no match: the rule looks noisy' : ''}.
        </Typography>
        <Box display="flex" gap={4} flexWrap="wrap" mb={2}>
            <Box>{countTable(r.by_project, 'Project (top 20)')}</Box>
            <Box>{countTable(r.by_object_type, 'Object type')}</Box>
        </Box>
        <Typography variant="subtitle2">Sample</Typography>
        <SimpleTable rows={r.sample} rowKey={s => s.object_id} empty="no hits" columns={[
            { label: 'Project', source: 'project' },
            { label: 'Object', render: s => <Link to={`/objects/${encodeURIComponent(s.object_id)}/show`}>{s.object}</Link> },
            { label: 'Type', source: 'type' },
            { label: 'File', source: 'file' },
            { label: 'Fields', source: 'fields' },
        ]} />
    </>
);

const LlmResult = ({ r }) => (
    <>
        <Typography gutterBottom>
            A run would send <b>{fmtNum(r.subjects_to_send)}</b> {r.target === 'object' ? 'objects' : 'fields'} in
            <b> {fmtNum(r.model_calls)}</b> model calls over {fmtNum(r.objects_scanned)} objects of {fmtNum(r.projects)} projects
            {r.truncated ? ' (truncated)' : ''}. Objects / fields with a verdict of the current rule version are not counted.
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>{r.note}</Typography>
        {countTable(r.by_project, 'Project (model calls, top 20)')}
    </>
);

const dryRunData = (kind, values, record, extra = {}) => {
    const data = { rule: ruleSpec(kind, values), sample: 20, ...extra };
    if (record && record.id) data.rule_id = record.id; else data.kind = kind;
    return data;
};

// POST /rules/dry_run with the form's current values (unsaved edits included): a new rule, or
// an existing one with the form as a patch. Keyword: predicted hits; LLM: the cost of a run.
export const DryRunButton = ({ kind, values }) => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const [open, setOpen] = useState(false);
    const [projects, setProjects] = useState([]);
    const [result, setResult] = useState(null);
    const [busy, setBusy] = useState(false);
    if (record && record.builtin === 'core') return null;

    const run = () => {
        const data = dryRunData(kind, values, record, projects.length ? { project_ids: projects.map(p => p.id) } : {});
        setBusy(true);
        dataProvider.dryRun({ data })
            .then(({ data: r }) => setResult(r))
            .catch(e => notify(e.message || 'Dry run failed', { type: 'warning' }))
            .finally(() => setBusy(false));
    };

    return (
        <>
            <Button label="Dry run" onClick={() => setOpen(true)} />
            <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="md" aria-labelledby="dry-run-title">
                <DialogTitle id="dry-run-title">Dry run: {values.name || 'new rule'}</DialogTitle>
                <DialogContent>
                    <Typography variant="body2" gutterBottom>
                        Evaluates the form as it is now on the stored main snapshots of the projects in rules mode.
                        Nothing is written.
                    </Typography>
                    <ProjectPicker multiple value={projects} onChange={setProjects} label="Only these projects (empty: all in scope)" />
                    {result && (
                        <Box mt={2}>
                            {result.note === 'no project in scope'
                                ? <Typography>No project in scope.</Typography>
                                : (result.kind === 'llm' ? <LlmResult r={result} /> : <KeywordResult r={result} />)}
                        </Box>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button label="Close" onClick={() => setOpen(false)} />
                    <Button label={result ? 'Run again' : 'Run'} onClick={run} disabled={busy} />
                </DialogActions>
            </Dialog>
        </>
    );
};

// "Count objects in scope": the same dry run, shown as one line next to the scope inputs.
export const ScopeCountButton = ({ kind, values }) => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const [state, setState] = useState(null);
    const run = () => {
        setState({ busy: true });
        dataProvider.dryRun({ data: dryRunData(kind, values, record, { sample: 0 }) })
            .then(({ data: r }) => setState(r.note === 'no project in scope' ? { text: 'No project in scope' }
                : { text: `${fmtNum(r.objects_scanned)} objects in ${fmtNum(r.projects)} projects${r.truncated ? ' (at least)' : ''}` }))
            .catch(e => setState({ text: e.message || 'Count failed', error: true }));
    };
    return (
        <Box display="flex" alignItems="center" gap={1} flexWrap="wrap" mb={1}>
            <Button label="Count objects in scope" onClick={run} disabled={!!(state && state.busy)} variant="outlined" size="small" />
            {state && !state.busy && <Typography variant="body2" color={state.error ? 'error' : 'text.secondary'}>{state.text}</Typography>}
            {state && state.busy && <Typography variant="body2" color="text.secondary">counting…</Typography>}
        </Box>
    );
};

// toolbar of the keyword rule form (the LLM form has its own in LlmRules.js)
export const RuleFormToolbar = ({ kind }) => {
    const record = useRecordContext();
    return (
        <Toolbar sx={{ gap: 2 }}>
            <SaveButton />
            <FormDataConsumer>{({ formData }) => <DryRunButton kind={kind} values={formData || {}} />}</FormDataConsumer>
            {record && record.id && record.builtin !== 'core' && (
                <Box ml="auto"><DeleteButton mutationMode="pessimistic" confirmTitle="Delete rule (its hits are kept)" /></Box>
            )}
        </Toolbar>
    );
};

const byStatus = (v, status) => (v.by_status && v.by_status[status]) || 0;

// GET /rules/stats?rule_id: hits by status and precision per rule version (aside of the edit page)
export const RuleStatsAside = () => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const state = useFetch(() => (record ? dataProvider.ruleStats({ ruleId: record.id }) : Promise.resolve({ data: [] })),
                           [record && record.id, record && record.version]);
    if (!record) return null;
    return (
        <Card sx={{ width: 420, ml: 2 }}>
            <CardHeader title="Statistics" subheader={<Link to={listUrl('hits', { rule_id: record.id, presence: 'all' })}>All hits of this rule</Link>} />
            <CardContent>
                <Loaded state={state}>
                    {data => {
                        const stats = (data || []).find(s => s.rule_id === record.id);
                        if (!stats) return <Typography variant="body2" color="text.secondary">No hits yet.</Typography>;
                        return (
                            <>
                                <SimpleTable rows={stats.versions} rowKey={v => String(v.version)} columns={[
                                    { label: 'Version', render: v => (v.version === stats.current_version ? `${v.version} (current)` : v.version) },
                                    { label: 'Open', render: v => byStatus(v, 'pending_review') + byStatus(v, 'need_more_info') },
                                    { label: statusLabel('match'), render: v => byStatus(v, 'match') },
                                    { label: statusLabel('no_match'), render: v => byStatus(v, 'no_match') },
                                    { label: 'Human', source: 'human_decisions' },
                                    { label: 'Precision', render: v => fmtPct(v.precision_human) },
                                    { label: 'w/o MCP', render: v => fmtPct(v.precision_human_without_mcp) },
                                ]} />
                                <Typography variant="caption" color="text.secondary">
                                    Precision = match / (match + no match) among human decisions; "w/o MCP" leaves out
                                    decisions made by agents.
                                </Typography>
                                {stats.top_reject_notes && stats.top_reject_notes.length > 0 && (
                                    <Box mt={2}>
                                        <Typography variant="subtitle2">Why hits were marked no match</Typography>
                                        <SimpleTable rows={stats.top_reject_notes} rowKey={n => n.note}
                                                     columns={[{ label: 'Note', source: 'note' }, { label: 'Hits', source: 'n' }]} />
                                    </Box>
                                )}
                            </>
                        );
                    }}
                </Loaded>
            </CardContent>
        </Card>
    );
};
