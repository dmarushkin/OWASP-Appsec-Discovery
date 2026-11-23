import React, { useEffect, useState } from 'react';
import { Button, Link, useDataProvider, useNotify } from 'react-admin';
import { Box, Chip, Grid, Stack, Tooltip, Typography } from '@mui/material';
// Detail panels of the admin home (PipelineHealth.js, collapsed sections) and of the rule studio (RuleRollouts
// with a ruleId): ParseScans (GET /scan_progress), LlmCoverage (GET /llm_progress), LlmRuns (GET /llm_runs),
// RuleRollouts (GET /llm_rollouts).
import {
    Ago, CountBar, LlmStateChip, Loaded, RunProgress, ScanStateChip, SimpleTable, TruncatedNote, fmtDate, fmtDuration, fmtNum,
    pluralize, shortSha, showUrl, useAutoRefresh, useFetch,
} from './common';
import {
    ROLLOUT_COLORS, executorLabel, llmStateLabel, purposeLabel, rolloutActionLabel, rolloutStatusLabel, scanStateLabel,
} from './choices';

const runRules = r => (r.rules ? r.rules.map(x => x.name || `#${x.id}`).join(', ') : 'all enabled rules');
// a service run taken over by a harness keeps its job id: say who took it
const runExecutor = r => [executorLabel[r.executor] || r.executor, r.purpose && r.purpose !== 'score' && (purposeLabel[r.purpose] || r.purpose),
    r.taken_over_by && `taken over by ${r.taken_over_by}`,
    r.released_from && `released from run ${r.released_from}`].filter(Boolean).join(' · ');
const runWhere = r => `${r.project_path || '?'} / ${r.mr_id ? `MR row ${r.mr_id}` : (r.branch_name || r.branch_id)}`;
const runStatus = r => (r.status === 'awaiting_answers' ? 'waits for a harness model' : r.status);

const runColumns = [
    { label: 'Job', render: r => <Link to={showUrl('jobs', r.id)}>{r.id}</Link> },
    { label: 'Rules', render: runRules },
    { label: 'Project / branch', render: runWhere },
    { label: 'Answered by', render: runExecutor },
    { label: 'Status', render: runStatus },
    { label: 'Progress', render: r => <RunProgress progress={r} /> },
    { label: 'Started', render: r => <Ago value={r.started_at || r.created_at} /> },
    { label: 'Finished', render: r => (r.finished_at ? <Ago value={r.finished_at} /> : '-') },
];

// GET /llm_runs: LLM rule runs with "N of M objects processed", refreshed while some are active
export const LlmRuns = () => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.llmRuns(), []);
    const active = !!(state.data && state.data.active && state.data.active.length);
    useAutoRefresh(active, state.reload, 5000);
    return (
        <Loaded state={state}>
            {data => (
                <>
                    <SimpleTable rows={data.active} rowKey={r => r.id} empty="No LLM rule run is active" columns={runColumns} />
                    <TruncatedNote shown={data.active.length} total={data.active_total ?? null} truncated={data.active.length >= 20 && data.active_total === undefined}
                                   what="active runs" hint="the API lists the first 20; the Jobs page has them all" />
                    {data.recent && data.recent.length > 0 && (
                        <Box mt={2}>
                            <Typography variant="subtitle2">Finished in the last 24 hours</Typography>
                            <SimpleTable rows={data.recent} rowKey={r => r.id} columns={runColumns} />
                            <TruncatedNote shown={data.recent.length} total={data.recent_total ?? null} truncated={data.recent.length >= 20 && data.recent_total === undefined}
                                           what="finished runs" hint="the API lists the first 20" />
                        </Box>
                    )}
                    {data.active.some(r => r.status === 'awaiting_answers') && (
                        <Typography variant="caption" color="text.secondary">
                            A run that waits for a harness model is answered by a harness connected to the MCP server
                            (<Link to="/harness">Harness work ▸ How to connect</Link>).
                        </Typography>
                    )}
                </>
            )}
        </Loaded>
    );
};

const MAIN_COUNTS = ['outdated', 'never_scanned', 'partial', 'failed', 'skipped', 'no_main'];
const COUNT_COLORS = { failed: 'error', partial: 'warning', running: 'info', queued: 'info', retrying: 'warning' };

const Counts = ({ data, keys, labelOf }) => (
    <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}>
        {keys.map(key => (
            <Chip key={key} size="small" label={`${labelOf(key)}: ${data[key] || 0}`}
                  color={data[key] ? (COUNT_COLORS[key] || 'default') : 'default'}
                  variant={data[key] ? 'filled' : 'outlined'} />
        ))}
    </Stack>
);

const scanActive = d => !!d && (d.main.queued + d.main.running + d.main.sync_queued + d.main.sync_running
    + d.mrs.queued + d.mrs.running + d.external.pending + d.external.running) > 0;

const PAGE = 25;

// GET /scan_progress: main branches up to date / behind / failed, open MRs; the projects behind or failed, paged.
export const ParseScans = () => {
    const dataProvider = useDataProvider();
    const [offset, setOffset] = useState(0);
    const [rows, setRows] = useState([]);
    const state = useFetch(() => dataProvider.scanProgress({ status: 'attention,outdated,never_scanned', limit: PAGE, offset }), [offset]);
    useEffect(() => {
        if (!state.data) return;
        const items = state.data.projects.items;
        setRows(prev => (offset === 0 ? items : [...prev.filter(r => !items.some(i => i.project_id === r.project_id)), ...items]));
    }, [state.data, offset]);
    useAutoRefresh(scanActive(state.data), () => { setOffset(0); return state.reload(); }, 10000);
    return (
        <Loaded state={state}>
            {d => {
                const mrs = d.mrs;
                const idle = mrs.active_24h !== undefined ? mrs.open - mrs.active_24h : mrs.open - (mrs.not_tracked || 0) - mrs.scanned_current - mrs.queued - mrs.running;
                return (
                    <Grid container spacing={2}>
                        <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2">Main branches ({d.main.projects} GitLab projects)</Typography>
                            <CountBar done={d.main.scanned_current} total={d.main.projects} label="up to date" />
                            <CountBar done={d.main.synced} total={d.main.projects}
                                      label={`re-read from GitLab for their latest activity${d.main.sync_queued + d.main.sync_running
                                          ? ` (${d.main.sync_queued} sync queued, ${d.main.sync_running} running)` : ''}`} />
                            <Counts data={d.main} keys={MAIN_COUNTS} labelOf={scanStateLabel} />
                            <Typography variant="caption" color="text.secondary" component="div" sx={{ mt: 1 }}>
                                {Object.entries(d.by_scan_mode).filter(([, t]) => t.projects)
                                    .map(([mode, t]) => `${mode}: ${t.scanned_current} of ${t.projects} up to date`).join(' · ')}
                                {d.last_projects_sync && ` · project list synced ${fmtDate(d.last_projects_sync.finished_at
                                    || d.last_projects_sync.created_at)} (${d.last_projects_sync.status})`}
                            </Typography>
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2">Open merge requests ({mrs.open})</Typography>
                            {mrs.active_24h !== undefined ? (
                                <CountBar done={mrs.active_scanned || 0} total={mrs.active_24h} label="MRs active in 24 h scanned" />
                            ) : (
                                <CountBar done={mrs.scanned_current} total={mrs.open - (mrs.not_tracked || 0)} label="tracked MRs with a current delta" />
                            )}
                            <Counts data={mrs} keys={['failed', 'partial', 'not_tracked', 'queued', 'running']}
                                    labelOf={k => ({ not_tracked: 'Not tracked', queued: 'Queued', running: 'Running' }[k] || scanStateLabel(k))} />
                            <Typography variant="caption" color="text.secondary" component="div" sx={{ mt: 1 }}>
                                {Math.max(0, idle)} idle MRs are not scanned by policy (no activity in the last day)
                                {d.external.projects > 0 && ` · ${pluralize(d.external.projects, 'pushed project')}, ${d.external.with_state} with a state;
                                    pushed batches ${d.external.pending} queued, ${d.external.running} running`}
                            </Typography>
                        </Grid>
                        <Grid item xs={12}>
                            <Typography variant="subtitle2" gutterBottom>Projects behind or failed ({d.projects.total})</Typography>
                            <SimpleTable rows={rows} rowKey={r => r.project_id}
                                         empty="Every main branch is up to date" columns={[
                                             { label: 'Project', render: r => <Link to={showUrl('projects', r.project_id)}>{r.project_path}</Link> },
                                             { label: 'Main branch', render: r => <ScanStateChip scan={r} /> },
                                             { label: 'Commit', render: r => shortSha(r.commit) },
                                             { label: 'Parsed', render: r => shortSha(r.scanned_commit) || 'never' },
                                             { label: 'Last parse', render: r => (r.last_scan_at ? <Ago value={r.last_scan_at} /> : '-') },
                                             { label: 'Job', render: r => (r.job_id ? <Link to={showUrl('jobs', r.job_id)}>{r.job_id}</Link>
                                                 : (r.last_job_id ? <Link to={showUrl('jobs', r.last_job_id)}>{r.last_job_id}</Link> : '')) },
                                             { label: 'Error', render: r => r.last_error || '' },
                                         ]} />
                            {d.projects.total > rows.length && (
                                <Button label={`Show more (${rows.length} of ${d.projects.total})`} onClick={() => setOffset(rows.length)} />
                            )}
                        </Grid>
                    </Grid>
                );
            }}
        </Loaded>
    );
};

const LLM_COUNTS = ['outdated', 'never', 'not_scanned', 'queued', 'running', 'awaiting_answers', 'failed'];
const LLM_COUNT_COLORS = { failed: 'error', never: 'warning', running: 'info', queued: 'info', awaiting_answers: 'info' };
const llmCountLabel = k => ({ queued: 'Queued', running: 'Running', awaiting_answers: 'Waits for a harness model' }[k]
    || llmStateLabel(k));

const llmActive = d => !!d && (d.main.queued + d.main.running + d.mrs.queued + d.mrs.running
    + Object.values(d.queue || {}).reduce((n, q) => n + q.pending + q.running, 0)) > 0;

// GET /llm_progress: projects in scan mode rules with current verdicts of every enabled LLM rule; per rule
// answered / total objects; the projects that failed, were never counted or have a run queued / running.
export const LlmCoverage = () => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.llmProgress({ status: 'failed,never,queued,running', limit: 10 }), []);
    useAutoRefresh(llmActive(state.data), state.reload, 10000);
    return (
        <Loaded state={state}>
            {d => (
                <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2">Main branches ({d.main.projects} projects in scan mode rules)</Typography>
                        <CountBar done={d.main.current} total={d.main.projects}
                                  label={`up to date for all ${pluralize(d.rules.length, 'LLM rule')}`} />
                        <CountBar done={d.main.answered} total={d.main.total} label="objects judged (all rules)" />
                        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}>
                            {LLM_COUNTS.map(key => (
                                <Chip key={key} size="small" label={`${llmCountLabel(key)}: ${d.main[key] || 0}`}
                                      color={d.main[key] ? (LLM_COUNT_COLORS[key] || 'default') : 'default'}
                                      variant={d.main[key] ? 'filled' : 'outlined'} />
                            ))}
                        </Stack>
                        <Tooltip title={`core prompts version ${d.prompt_version}`}>
                            <Typography variant="caption" color="text.secondary" component="div" sx={{ mt: 1 }}>
                                Open MRs: {d.mrs.current} of {d.mrs.open} up to date
                                {d.mrs.queued + d.mrs.running ? ` (${d.mrs.queued + d.mrs.running} queued / running)` : ''}
                                {d.last_computed_at && ` · counted ${fmtDate(d.last_computed_at)}`}
                            </Typography>
                        </Tooltip>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2">
                            <Link to="/llm_rules">Per rule (objects judged, main branches)</Link>
                        </Typography>
                        {d.rules.length === 0 && (
                            <Typography variant="body2" color="text.secondary">No LLM rule is enabled</Typography>
                        )}
                        {d.rules.map(r => (
                            <Box key={r.id} sx={{ mt: 1 }}>
                                <Typography variant="body2">
                                    {r.name} <Typography component="span" variant="caption" color="text.secondary">
                                        v{r.version}, {r.target}: {r.projects_current} of {r.projects} projects up to date
                                        {r.pending_external ? `, ${r.pending_external} wait for a harness model` : ''}
                                        {r.failed ? `, ${r.failed} failed` : ''}
                                    </Typography>
                                </Typography>
                                <CountBar done={r.answered} total={r.total} label="judged" />
                            </Box>
                        ))}
                    </Grid>
                    <Grid item xs={12}>
                        <SimpleTable rows={d.projects.items} rowKey={r => r.project_id}
                                     empty="No project failed, waits for a run or was never counted" columns={[
                                         { label: 'Project', render: r => <Link to={showUrl('projects', r.project_id)}>{r.project_path}</Link> },
                                         { label: 'LLM rules', render: r => <LlmStateChip llm={r} /> },
                                         { label: 'Remaining', render: r => r.remaining },
                                         { label: 'Last run', render: r => (r.last_job_at ? <Ago value={r.last_job_at} /> : '-') },
                                         { label: 'Job', render: r => (r.job_id ? <Link to={showUrl('jobs', r.job_id)}>{r.job_id}</Link>
                                             : (r.last_job_id ? <Link to={showUrl('jobs', r.last_job_id)}>{r.last_job_id}</Link> : '')) },
                                         { label: 'Error', render: r => r.last_error || '' },
                                     ]} />
                        <TruncatedNote shown={d.projects.items.length} total={d.projects.total} what="projects"
                                       hint="the first ones by state; narrow the scope for the rest" />
                        {d.last_computed_at && <Typography variant="caption" color="text.secondary" component="div">counted {fmtDate(d.last_computed_at)}</Typography>}
                    </Grid>
                </Grid>
            )}
        </Loaded>
    );
};

// ---- rule rollouts (GET /llm_rollouts): the old verdicts of a rule re-judged in budgeted slices ------------------

const ROLLOUT_ACTIONS = { planned: ['start', 'cancel'], running: ['pause', 'cancel'], paused: ['resume', 'cancel'] };

// "Why not faster": a human's pause, the budget, fresh work, the harness, or nothing but the kept verdicts
// (progress.waiting is the scanner's free text: "calls budget of the hour used (120/h)", "fresh work first: ...")
const whyNotFaster = r => {
    const p = r.progress || {};
    const budget = (p.budget_effective || {}).calls_per_hour || (r.budget || {}).calls_per_hour;
    const waiting = String(p.waiting || '');
    if (r.status === 'paused') return `paused${r.paused_reason ? `: ${r.paused_reason}` : ' by a human'}`;
    if (/budget/i.test(waiting)) return `budget reached: ${fmtNum(p.calls_last_hour || 0)}/${fmtNum(budget)} calls this hour`;
    if (/fresh work/i.test(waiting)) return waiting.replace('llm_score jobs', 'service runs');
    if (/harness|external/i.test(waiting)) return 'waiting for the harness';
    if (waiting) return waiting;
    if (p.protected_human !== undefined || p.protected_harness !== undefined) {
        return `${p.protected_human || 0} human and ${p.protected_harness || 0} harness verdicts kept (never overwritten)`;
    }
    return '';
};

export const RuleRollouts = ({ ruleId }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const state = useFetch(() => dataProvider.rollouts(ruleId ? { rule_id: ruleId, limit: 20 } : { limit: 20 }), [ruleId]);
    const running = !!(state.data && state.data.items.some(r => r.status === 'running'));
    useAutoRefresh(running, state.reload, 15000);
    const act = (r, action) => dataProvider.rolloutAction({ id: r.id, action, data: {} })
        .then(() => { notify(`Rollout of ${r.rule_name}: ${rolloutActionLabel[action] || action}`, { type: 'info' }); state.reload(); })
        .catch(e => notify(e.message || 'Failed', { type: 'error' }));
    return (
        <Loaded state={state}>
            {data => (
                <SimpleTable rows={data.items} rowKey={r => r.id} empty="No open rollout" columns={[
                    { label: 'Rule', render: r => <Link to={`/llm_rules/${r.rule_id}?tab=versions`}>{r.rule_name}</Link> },
                    { label: 'Version', render: r => `v${r.from_version ?? '-'} → v${r.to_version}` },
                    { label: 'Status', render: r => <Chip size="small" variant="outlined" label={rolloutStatusLabel(r.status)} color={ROLLOUT_COLORS[r.status] || 'default'} /> },
                    { label: 'Progress', render: r => {
                        const p = r.progress || {};
                        const planned = p.planned_objects || 0;
                        return planned ? <CountBar done={Math.max(0, planned - (p.remaining_objects || 0))} total={planned} label="objects" width={200} />
                            : (r.status === 'done' ? 'done' : '-');
                    } },
                    { label: 'Calls this hour / budget', render: r => {
                        const p = r.progress || {};
                        const b = p.budget_effective || {};
                        return `${fmtNum(p.calls_last_hour || 0)} / ${fmtNum(b.calls_per_hour || (r.budget || {}).calls_per_hour)}`;
                    } },
                    { label: 'ETA', render: r => (r.status === 'running' ? fmtDuration((r.progress || {}).eta_s) : '') },
                    { label: 'Why not faster', render: whyNotFaster },
                    { label: '', render: r => (ROLLOUT_ACTIONS[r.status] || []).map(a => (
                        <Button key={a} size="small" label={rolloutActionLabel[a] || a} onClick={() => act(r, a)} />)) },
                ]} />
            )}
        </Loaded>
    );
};
