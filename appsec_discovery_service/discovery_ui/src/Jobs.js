import React, { useState } from 'react';
import {
    AutocompleteInput, Button, Datagrid, FunctionField, Link, List, ReferenceInput, Show, TextField, TextInput, SelectInput,
    TopToolbar, useDataProvider, useListContext, useNotify, useRecordContext, useRedirect, useRefresh,
} from 'react-admin';
import { Chip, Collapse, Grid, Stack, Tab, Tabs, Typography } from '@mui/material';
import { JOB_STATUS_COLORS, jobKindChoices, jobKindLabel, jobStatusChoices, jobStatusLabel } from './choices';
import {
    Ago, Clipped, RunErrors, RunProgress, SimpleTable, fmtDate, fmtDuration, listUrl, showUrl, useAutoRefresh,
} from './common';

// Jobs (W4): the scanner's queue as a list with quick tabs Active / Failed 24 h / All; a job page with Retry
// (failed) and Cancel (waiting). The subject (project, branch, MR, rules) is resolved by the API (job.subject).

const TABS = {
    active: { label: 'Active', filter: { status: ['pending', 'running'] }, sort: { field: 'created_at', order: 'ASC' } },
    failed: { label: 'Failed', filter: { status: 'failed' }, sort: { field: 'finished_at', order: 'DESC' } },
    all: { label: 'All', filter: {}, sort: { field: 'id', order: 'DESC' } },
};
const tabOf = filter => {
    const s = filter.status;
    if (Array.isArray(s) && s.includes('pending') && s.includes('running')) return 'active';
    if (s === 'failed') return 'failed';
    return 'all';
};

const QueueTabs = () => {
    const { filterValues, setFilters, displayedFilters, setSort } = useListContext();
    const select = (e, value) => {
        const { status, ...kept } = filterValues;
        setFilters({ ...kept, ...TABS[value].filter }, displayedFilters);
        setSort(TABS[value].sort);
    };
    return (
        <Tabs value={tabOf(filterValues)} onChange={select} sx={{ px: 1 }}>
            {Object.entries(TABS).map(([id, t]) => <Tab key={id} value={id} label={t.label} />)}
        </Tabs>
    );
};

// the project filter (GET /jobs?filter={"project_id": id}): the jobs of one project, whatever their kind
const filters = [
    <TextInput source="q" label="Error text" alwaysOn />,
    <SelectInput source="kind" choices={jobKindChoices} alwaysOn />,
    <ReferenceInput source="project_id" reference="projects" alwaysOn>
        <AutocompleteInput optionText="full_path" filterToQuery={q => ({ q })} label="Project" />
    </ReferenceInput>,
    <SelectInput source="status" choices={jobStatusChoices} />,
];

const isActive = r => r && (r.status === 'pending' || r.status === 'running'
    || (r.progress && r.progress.phase === 'awaiting_answers'));

// refreshes the list every 5 s while a job on the page is active (progress of LLM runs)
const ListAutoRefresh = () => {
    const { data } = useListContext();
    const refresh = useRefresh();
    useAutoRefresh(!!(data && data.some(isActive)), refresh, 5000);
    return null;
};

const ShowAutoRefresh = () => {
    const record = useRecordContext();
    const refresh = useRefresh();
    useAutoRefresh(isActive(record), refresh, 5000);
    return null;
};

// scan_branch / scan_mr phases (waiting -> clone -> parse -> save -> done | skipped | partial | failed); a diff-based
// skip (progress.skipped: no parser file changed since the snapshot, nothing cloned) names the changed file count,
// a full scan says why it was not skipped (progress.full_scan_reason)
const phaseOf = p => [
    p.skipped ? `skipped: ${p.skipped} (${p.changed_files || 0} files)` : p.phase,
    p.full_scan_reason && `full scan: ${p.full_scan_reason}`,
    p.objects !== undefined && `${p.objects} objects`,
    p.by_parser && Object.keys(p.by_parser).length > 0
        && Object.entries(p.by_parser).map(([k, n]) => `${k} ${n}`).join(', '),
    p.failed_parsers && p.failed_parsers.length > 0 && `failed: ${p.failed_parsers.join(', ')}`,
    !p.skipped && p.reason, p.error,
].filter(Boolean).join(' · ');

// the cause of a failed / incomplete job for the list: last_error, else the progress summary
const errorOf = r => r.last_error || (r.progress && r.progress.error) || '';

const progressOf = r => {
    if (!r.progress) return '-';
    if (r.progress.total_objects !== undefined) return <RunProgress progress={r.progress} width={180} />;
    return r.progress.phase ? phaseOf(r.progress) : '-';
};

const statusOf = r => {
    if (r.status === 'pending' && r.attempts > 0) return 'Retrying';
    if (r.status === 'done' && r.progress && r.progress.phase === 'awaiting_answers') return 'Waits for a harness model';
    return jobStatusLabel(r.status);
};
const JobStatusChip = ({ job }) => (
    <Chip size="small" label={statusOf(job)} variant="outlined"
          color={job.status === 'pending' && job.attempts > 0 ? 'warning' : (JOB_STATUS_COLORS[job.status] || 'default')} />
);

// job.subject = { project_id, project_path, branch_name, mr_iid, rule_names } (null for kinds without one)
const subjectText = r => {
    const s = r.subject;
    if (!s) return '-';
    const where = [s.project_path, s.mr_iid ? `!${s.mr_iid}` : s.branch_name].filter(Boolean).join(' · ');
    const rules = (s.rule_names || []).join(', ');
    return [where, rules].filter(Boolean).join(' · ') || '-';
};
// the subject with the project as a link to its page
const SubjectCell = ({ job }) => {
    const s = job.subject;
    if (!s) return <span>-</span>;
    const rest = [s.mr_iid ? `!${s.mr_iid}` : s.branch_name, (s.rule_names || []).join(', ')].filter(Boolean).join(' · ');
    return (
        <span>
            {s.project_path && (s.project_id
                ? <Link to={showUrl('projects', s.project_id)} onClick={e => e.stopPropagation()}>{s.project_path}</Link>
                : s.project_path)}
            {s.project_path && rest ? ' · ' : ''}{rest}
        </span>
    );
};

// run time from started_at (kept on finished rows; locked_at is the lease and is cleared at the end)
const startOf = r => r.started_at || r.locked_at;
const durationOf = r => {
    if (!startOf(r)) return '-';
    const end = r.finished_at ? new Date(r.finished_at) : new Date();
    return fmtDuration((end - new Date(startOf(r))) / 1000);
};

export const JobList = () => (
    <List filters={filters} filterDefaultValues={TABS.active.filter} sort={TABS.active.sort} title="Jobs" perPage={25}>
        <QueueTabs />
        <ListAutoRefresh />
        <Datagrid rowClick="show" bulkActionButtons={false}>
            <TextField source="id" />
            <FunctionField label="Kind" sortBy="kind" render={r => jobKindLabel(r.kind)} />
            <FunctionField label="Status" sortBy="status" render={r => <JobStatusChip job={r} />} />
            <FunctionField label="Subject" render={r => <SubjectCell job={r} />} />
            <FunctionField label="Progress" render={progressOf} />
            <FunctionField label="Duration" render={durationOf} />
            <FunctionField label="Created" sortBy="created_at" render={r => <Ago value={r.created_at} />} />
            <FunctionField label="Error" render={r => (errorOf(r) ? <Clipped text={errorOf(r)} max={120} /> : '')} />
        </Datagrid>
    </List>
);

// ---- job page ---------------------------------------------------------------------------------------------------

const JobActions = () => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    const redirect = useRedirect();
    const [busy, setBusy] = useState(false);
    if (!record) return null;
    const retry = () => {
        setBusy(true);
        dataProvider.retryJob({ id: record.id })
            .then(() => { notify(`Job #${record.id} queued again`, { type: 'info' }); refresh(); })
            .catch(e => notify(e.message || 'Retry failed', { type: 'error' }))
            .finally(() => setBusy(false));
    };
    const cancel = () => {
        if (!window.confirm(`Cancel job #${record.id}? It ends as failed and is not run.`)) return;
        setBusy(true);
        dataProvider.cancelJob({ id: record.id })
            .then(() => { notify(`Job #${record.id} cancelled`, { type: 'info' }); refresh(); })
            .catch(e => notify(e.message || 'Cancel failed', { type: 'error' }))
            .finally(() => setBusy(false));
    };
    return (
        <TopToolbar>
            <Button label="Back to jobs" onClick={() => redirect('list', 'jobs')} />
            {record.status === 'failed' && <Button label="Retry" variant="contained" onClick={retry} disabled={busy} />}
            {record.status === 'pending' && <Button label="Cancel" color="error" onClick={cancel} disabled={busy} />}
        </TopToolbar>
    );
};

const Row = ({ label, children }) => (
    <Grid container spacing={1} sx={{ py: 0.5 }}>
        <Grid item xs={4} sm={3}><Typography variant="body2" color="text.secondary">{label}</Typography></Grid>
        <Grid item xs={8} sm={9}><Typography variant="body2" component="div">{children}</Typography></Grid>
    </Grid>
);

const SubjectLinks = ({ job }) => {
    const s = job.subject || {};
    const payload = job.payload || {};
    const ruleIds = payload.rule_ids || [];
    const links = [
        s.project_path && <Link key="p" to={s.project_id ? showUrl('projects', s.project_id) : listUrl('projects', { q: s.project_path })}>Project</Link>,
        s.project_id && <Link key="j" to={listUrl('jobs', { project_id: s.project_id })}>Jobs of the project</Link>,
        s.project_id && <Link key="o" to={listUrl('objects', { project_id: s.project_id })}>Objects</Link>,
        ruleIds.length > 0 && <Link key="h" to={listUrl('hits', { rule_id: ruleIds.length === 1 ? ruleIds[0] : ruleIds, presence: 'all' })}>Hits of the rule</Link>,
    ].filter(Boolean);
    return (
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <span>{subjectText(job)}</span>
            {links}
        </Stack>
    );
};

// what failed inside the job: the parsers of a partial scan (progress.parser_errors), the objects of an LLM run
// (progress.errors / progress.error, also when the job ended done or incomplete)
const JobErrors = ({ job }) => {
    const p = job.progress || {};
    const parserErrors = p.parser_errors && Object.keys(p.parser_errors).length ? p.parser_errors : null;
    const summary = p.error && p.error !== job.last_error ? p.error : null;
    const hasObjects = p.errors && (p.errors.total || (p.errors.items || []).length);
    if (!parserErrors && !summary && !hasObjects) return null;
    return (
        <div>
            <Typography variant="h6" gutterBottom>What failed</Typography>
            {parserErrors && (
                <SimpleTable rows={Object.entries(parserErrors).map(([parser, error]) => ({ parser, error }))} rowKey={r => r.parser}
                             columns={[{ label: 'Parser', source: 'parser' }, { label: 'Error', render: r => <Clipped text={r.error} max={200} /> }]} />
            )}
            {(summary || hasObjects) && (
                <Typography variant="body2" color="text.secondary" gutterBottom>
                    {p.failed_objects ? `${p.failed_objects} of ${p.total_objects || '?'} objects got no verdict` : 'Objects that got no verdict'}
                    {hasObjects ? ` (first ${(p.errors.items || []).length} listed, counts by error class):` : ':'}
                </Typography>
            )}
            <RunErrors errors={p.errors} summary={summary} />
        </div>
    );
};

const JobBody = () => {
    const job = useRecordContext();
    const [raw, setRaw] = useState(false);
    if (!job) return null;
    return (
        <Stack spacing={2} sx={{ p: 2 }}>
            <ShowAutoRefresh />
            <div>
                <Typography variant="h6" gutterBottom>Summary</Typography>
                <Row label="Kind">{jobKindLabel(job.kind)}</Row>
                <Row label="Status"><JobStatusChip job={job} /></Row>
                <Row label="Subject"><SubjectLinks job={job} /></Row>
                <Row label="Progress">{progressOf(job)}</Row>
            </div>
            <div>
                <Typography variant="h6" gutterBottom>Timing</Typography>
                <Row label="Created">{fmtDate(job.created_at)}</Row>
                {job.run_after && job.status === 'pending' && new Date(job.run_after) > new Date() && <Row label="Runs after">{fmtDate(job.run_after)}</Row>}
                <Row label="Started">{startOf(job) ? `${fmtDate(startOf(job))}${job.locked_by ? ` by ${job.locked_by}` : ''}` : '-'}</Row>
                <Row label="Finished">{job.finished_at ? fmtDate(job.finished_at) : '-'}</Row>
                <Row label="Duration">{durationOf(job)}</Row>
                <Row label="Attempts">{job.attempts} of {job.max_attempts}</Row>
            </div>
            <div>
                <Typography variant="h6" gutterBottom>Error</Typography>
                <pre style={{ whiteSpace: 'pre-wrap', margin: 0, fontSize: 12 }}>{job.last_error || 'none'}</pre>
                {job.payload && job.payload.previous_error && (
                    <Typography variant="caption" color="text.secondary">before the retry: {job.payload.previous_error}</Typography>
                )}
            </div>
            <JobErrors job={job} />
            <div>
                <Button label={`${raw ? 'Hide' : 'Show'} raw payload and progress`} onClick={() => setRaw(!raw)} />
                <Collapse in={raw}>
                    <Typography variant="caption" color="text.secondary">dedup key: {job.dedup_key || '-'}</Typography>
                    <pre style={{ margin: 0, fontSize: 12 }}>{JSON.stringify({ payload: job.payload, progress: job.progress }, null, 2)}</pre>
                </Collapse>
            </div>
        </Stack>
    );
};

const JobTitle = () => {
    const job = useRecordContext();
    return <span>{job ? `Job #${job.id}` : 'Job'}</span>;
};

export const JobShow = () => (
    <Show title={<JobTitle />} actions={<JobActions />}>
        <JobBody />
    </Show>
);
