import React, { useMemo, useState } from 'react';
import { Link, Title, useDataProvider } from 'react-admin';
import {
    Box, Button, Checkbox, FormControlLabel, Grid, Stack, Table, TableBody, TableCell, TableHead, TableRow,
    TextField as MuiTextField, Tooltip, Typography,
} from '@mui/material';
import { QUEUE_IDS, openQueueFilter, openStatuses, queueCounts, queueFilter, queueLabel } from './choices';
import {
    AsOf, CountBar, DetailsSection, HealthChip, Loaded, Panel, SimpleTable, StatTile, TrialMetricChips, TruncatedNote, fmtAgo,
    fmtDate, fmtDuration, fmtNum, fmtPct, listUrl, pluralize, trialVerdict, useFetch, useSnapshot,
} from './common';
import { scopedTitle, useScope } from './scope';

// Datasec home: what waits for me, what to decide together, what is new, what to accept. Sources: one
// GET /hits/aggregate (by queue x rule: the tiles and "Open hits by rule" - the same queue definition as the Review tabs
// and the menu badge), GET /hits/clusters (the biggest clusters to decide), GET /llm_quality (questions age, rule
// health), GET /prompt_proposals?status=open, GET /llm_rollouts, GET /hits/aggregate (new matches in 24 h),
// GET /llm_progress (coverage). The statistics come from the scanner's snapshots ("updated N s ago").

const RULES_MAX = 10;
const DAY_MS = 24 * 3600 * 1000;
const CLUSTERS_TOP = 10;
const RULE_ROWS_MAX = 50;

const studio = (ruleId, tab) => `/llm_rules/${ruleId}?tab=${tab}`;
const sum = (rows, key) => (rows || []).reduce((n, r) => n + (Number(r[key]) || 0), 0);
const within24h = at => at && (Date.now() - new Date(at).getTime()) < DAY_MS;
const review = (tab, extra) => listUrl('hits', queueFilter(tab, extra));
const TODECIDE = { status: openStatuses, asked_by_model: false, field_marks: false };

// one GET /prompt_proposals?status=open; until the API has it (404), the per-rule fan-out
const useOpenProposals = () => {
    const dataProvider = useDataProvider();
    const fanOut = () => dataProvider.getList('llm_rules', {
        pagination: { page: 1, perPage: RULES_MAX }, sort: { field: 'id', order: 'ASC' }, filter: {},
    }).then(({ data: rules }) => Promise.all(rules.map(rule => dataProvider.proposals({ ruleId: rule.id })
        .then(p => p.data.items.filter(x => x.status === 'open').map(x => ({ ...x, rule_id: rule.id, rule_name: rule.name })))))
        .then(lists => ({ data: { items: lists.flat(), truncated: rules.length >= RULES_MAX } })));
    return useFetch(() => (typeof dataProvider.openProposals === 'function'
        ? dataProvider.openProposals().catch(e => (e.status === 404 || e.status === 405 ? fanOut() : Promise.reject(e)))
        : fanOut()), []);
};

// GET /hits/aggregate?by=queue,rule_id (the queues hide field marks and count live hits): totals and per rule
const useQueues = scope => {
    const dataProvider = useDataProvider();
    return useFetch(() => dataProvider.hitsAggregate({ by: ['queue', 'rule_id'], filter: { field_marks: false } }).then(({ data }) => {
        const byRule = {};
        (data.rows || []).forEach(r => {
            if (!QUEUE_IDS.includes(r.queue)) return;
            const x = byRule[r.rule_id] || (byRule[r.rule_id] = { rule_id: r.rule_id, name: r.rule_name || `rule #${r.rule_id}`, questions: 0, pending: 0, unsure: 0 });
            x[r.queue] += Number(r.n) || 0;
        });
        const rules = Object.values(byRule).map(x => ({ ...x, open: x.questions + x.pending + x.unsure }))
            .sort((a, b) => b.questions - a.questions || b.open - a.open);
        return { data: { totals: queueCounts(data.rows), rules, truncated: data.truncated, computed_at: data.computed_at, snapshot: data.snapshot } };
    }), [scope]);
};

// ---- Today -----------------------------------------------------------------------------------------------------

const Today = ({ queues, quality, proposals, rollouts, clusters }) => {
    const t = queues.data ? queues.data.totals : null, q = quality.data;
    const questions = t ? t.questions : null;
    const pending = t ? t.pending : null;
    const unsure = t ? t.unsure : null;
    const hasPending = q && q.rules.some(r => r.escalation_pending !== undefined);
    const queued = q ? (hasPending ? sum(q.rules, 'escalation_pending') : ((q.backlog.by_sample || {}).escalation || 0)) : null;
    const notScheduled = unsure !== null && queued !== null ? Math.max(unsure - queued, 0) : null;
    const oldest = q && q.totals.oldest_question_s ? fmtDuration(q.totals.oldest_question_s) : null;
    const proposalsOpen = proposals.data ? proposals.data.items.length : null;
    const running = rollouts.data ? rollouts.data.items.length : null;
    const needs = q ? q.totals.needs_improvement : null;
    const firstNeeding = q && q.rules.find(r => r.needs_improvement);
    const c = clusters.data;
    const top = c && c.items[0];

    const cta = questions ? { label: `Answer ${pluralize(questions, 'question')}`, to: review('questions') }
        : (pending + unsure ? { label: `Decide ${pluralize(pending + unsure, 'open hit')}${c ? ` in ${fmtNum(c.total_clusters)} clusters` : ''}`, to: listUrl('hits', TODECIDE) } : null);
    const busy = [queues, quality].some(s => s.loading && s.data === undefined);

    return (
        <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={2}>
                <StatTile title={queueLabel('questions')} value={questions} level={questions ? 'warning' : 'ok'}
                          sub1={[oldest ? `oldest ${oldest}` : null, 'from the harness model'].filter(Boolean).join(' · ')}
                          to={review('questions')} linkLabel="Answer" />
            </Grid>
            <Grid item xs={12} sm={6} md={2}>
                <StatTile title="Clusters to decide" value={c ? `${fmtNum(c.total_clusters)}${c.truncated ? '+' : ''}` : null} level={c && c.total_clusters ? 'warning' : 'ok'}
                          sub1={top ? `top: ${fmtNum(top.n_open)} hits in ${pluralize(top.projects, 'project')}` : 'same schema across services'}
                          to={listUrl('hits', TODECIDE)} linkLabel="Decide" />
            </Grid>
            <Grid item xs={12} sm={6} md={2}>
                <StatTile title={`${queueLabel('pending')} review`} value={pending} level={pending ? 'warning' : 'ok'} sub1="hits of review-mode rules"
                          to={review('pending')} linkLabel="Clusters" />
            </Grid>
            <Grid item xs={12} sm={6} md={2}>
                <StatTile title={queueLabel('unsure')} value={unsure} level={notScheduled ? 'info' : 'ok'}
                          sub1={queued === null ? 'service model unsure' : (
                              <Tooltip title="Queued: a check for the harness model exists. Not scheduled: checks are off, the daily escalation cap was reached, or the rule version changed since; a harness picks them up once checks are scheduled again.">
                                  <span>harness will check: {fmtNum(queued)} queued / {fmtNum(notScheduled)} not scheduled</span>
                              </Tooltip>)}
                          to={review('unsure')} linkLabel="Clusters" />
            </Grid>
            <Grid item xs={12} sm={6} md={2}>
                <StatTile title="Proposals" value={proposalsOpen} level={proposalsOpen ? 'info' : 'ok'} sub1="prompt changes waiting for you"
                          to="#proposals" linkLabel="Proposals" />
            </Grid>
            <Grid item xs={12} sm={6} md={2}>
                <StatTile title="Rules" value={needs} level={needs ? 'warning' : 'ok'} sub1={`need improvement${running ? ` · ${pluralize(running, 'rollout')} running` : ''}`}
                          to={firstNeeding ? studio(firstNeeding.rule_id, 'health') : '#health'} linkLabel="Health" />
            </Grid>
            <Grid item xs={12}>
                <Box display="flex" gap={1} alignItems="center" flexWrap="wrap">
                    {cta
                        ? <Button component={Link} to={cta.to} variant="contained" size="small">{cta.label}</Button>
                        : <Button variant="contained" size="small" disabled>{busy ? 'Loading…' : 'Queue is empty'}</Button>}
                    {queues.data && <AsOf value={queues.data.computed_at} snapshot={queues.data.snapshot} prefix="counts updated" />}
                    {[queues, quality, proposals, rollouts, clusters].filter(s => s.error).map((s, i) => (
                        <Typography key={i} variant="caption" color="error">{s.error.message || 'A request failed'}</Typography>
                    ))}
                </Box>
            </Grid>
        </Grid>
    );
};

// ---- Clusters to decide ------------------------------------------------------------------------------------------------

const ClustersToDecide = ({ clusters }) => (
    <Loaded state={clusters} skeleton={4}>
        {c => (
            <Stack spacing={1}>
                <SimpleTable rows={c.items} rowKey={i => i.cluster} empty="No open hit waits for a decision." columns={[
                    { label: 'Cluster', render: i => <Link to={listUrl('hits', { ...TODECIDE, cluster: i.cluster, view: 'list' })}>{i.label || i.key}</Link> },
                    { label: 'Rule', render: i => i.rule_name || '-' },
                    { label: 'Open', render: i => fmtNum(i.n_open) },
                    { label: 'Projects', render: i => `${fmtNum(i.projects)}${i.groups && i.groups.length ? ` (${i.groups.join(', ')}${i.projects > i.groups.length ? ', …' : ''})` : ''}` },
                    { label: 'In main', render: i => fmtPct(i.in_main_share) },
                    { label: 'New 7 d', render: i => fmtNum(i.new_7d) },
                    { label: 'Questions', render: i => i.questions || 0 },
                    { label: '', render: i => <Button component={Link} size="small" to={listUrl('hits', { ...TODECIDE, cluster: i.cluster, view: 'list' })}>Decide</Button> },
                ]} />
                <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
                    <TruncatedNote shown={c.items.length} total={c.total_clusters} what="clusters (same schema)" hint="the biggest first" />
                    <Link to={listUrl('hits', TODECIDE)}>→ all clusters (by schema, field, name or rule × group)</Link>
                    <AsOf value={c.computed_at} snapshot={false} />
                </Stack>
            </Stack>
        )}
    </Loaded>
);

// ---- Open hits by rule --------------------------------------------------------------------------------------------

const OpenByRule = ({ queues }) => {
    const rows = queues.rules.filter(r => r.open);
    const cell = (r, tab, n) => (n ? <Link to={review(tab, { rule_id: r.rule_id })}>{fmtNum(n)}</Link> : <span>0</span>);
    return (
        <Stack spacing={1}>
            <SimpleTable rows={rows.slice(0, RULE_ROWS_MAX)} rowKey={r => r.rule_id} empty="No open hit. Nothing waits for a decision." columns={[
                { label: 'Rule', render: r => <Link to={studio(r.rule_id, 'definition')}>{r.name}</Link> },
                { label: queueLabel('questions'), render: r => cell(r, 'questions', r.questions) },
                { label: queueLabel('pending'), render: r => cell(r, 'pending', r.pending) },
                { label: queueLabel('unsure'), render: r => cell(r, 'unsure', r.unsure) },
                { label: 'Open', render: r => <Link to={listUrl('hits', openQueueFilter({ rule_id: r.rule_id }))}>{fmtNum(r.open)}</Link> },
            ]} />
            <TruncatedNote shown={Math.min(rows.length, RULE_ROWS_MAX)} total={rows.length} truncated={queues.truncated} what="rules" />
        </Stack>
    );
};

// ---- New in 24 h ---------------------------------------------------------------------------------------------------

const NewIn24h = ({ matches, since, quality, proposals, rolloutsDone }) => {
    const asked = quality.data ? sum(quality.data.rules, 'asked_human_30d') : null;
    const newProposals = proposals.data ? proposals.data.items.filter(p => within24h(p.created_at)).length : null;
    const done = rolloutsDone.data ? rolloutsDone.data.items.filter(r => within24h(r.finished_at || r.updated_at || r.created_at)).length : null;
    const part = (n, text) => (n === null || n === undefined ? null : `${fmtNum(n)} ${text}`);
    return (
        <Stack spacing={0.5}>
            <Typography variant="body1">
                <Loaded state={matches} skeleton={1}>{n => <Link to={listUrl('hits', { status: 'match', presence: 'all', first_seen_after: since, view: 'list' })}>{fmtNum(n)} new matches</Link>}</Loaded>
            </Typography>
            <Typography variant="body2" color="text.secondary">
                {[part(asked, 'questions asked (30 d)'), part(done, 'rollouts finished'), part(newProposals, 'new proposals')].filter(Boolean).join(' · ') || '…'}
            </Typography>
        </Stack>
    );
};

// ---- Rule health ------------------------------------------------------------------------------------------------------

const HEAD = [
    ['Rule', ''],
    ['Health', 'OK: the harness model agrees with the service model often enough; Needs improvement: below the threshold with enough samples; Not enough samples: too few checks in 30 days'],
    ['Agreement 30d', 'Share of the QA sample (confident service verdicts) the harness model confirmed in the last 30 days, and the number of samples'],
    ['Escalation', 'Share of the service model\'s current verdicts that were "needs more info" (every one goes to the harness model, up to the daily cap per rule)'],
    ['Harness decisions', 'Hits whose current decision is the harness model\'s'],
    ['Questions', 'Open questions the harness model asked a human about this rule'],
    ['Checks queued', 'Checks waiting for a harness model: service-unsure hits escalated to it (plus QA samples)'],
    ['', ''],
];

const RuleHealthTable = ({ quality }) => {
    const [showDisabled, setShowDisabled] = useState(false);
    const [onlyAttention, setOnlyAttention] = useState(() => quality.rules.length > 15);
    const [q, setQ] = useState('');
    const rows = useMemo(() => quality.rules.filter(r => showDisabled || r.enabled !== false)
        .filter(r => !onlyAttention || r.needs_improvement || r.questions_open || r.health === 'not_enough_samples')
        .filter(r => !q || (r.rule_name || '').toLowerCase().includes(q.toLowerCase()))
        .sort((a, b) => Number(b.needs_improvement) - Number(a.needs_improvement)
            || (b.questions_open - a.questions_open) || (b.backlog - a.backlog)), [quality.rules, showDisabled, onlyAttention, q]);
    const hidden = quality.rules.length - quality.rules.filter(r => r.enabled !== false).length;
    return (
        <Stack spacing={1}>
            <Box display="flex" justifyContent="flex-end" alignItems="center" gap={1} flexWrap="wrap">
                <MuiTextField size="small" label="Search rule" value={q} onChange={e => setQ(e.target.value)} sx={{ minWidth: 200 }} />
                <FormControlLabel label={<Typography variant="caption">only rules that need attention</Typography>}
                                  control={<Checkbox size="small" checked={onlyAttention} onChange={e => setOnlyAttention(e.target.checked)} />} />
                <FormControlLabel label={<Typography variant="caption">show disabled{hidden ? ` (${hidden})` : ''}</Typography>}
                                  control={<Checkbox size="small" checked={showDisabled} onChange={e => setShowDisabled(e.target.checked)} />} />
            </Box>
            {!rows.length && <Typography variant="body2" color="text.secondary">{quality.rules.length ? 'No rule matches (every rule is healthy, or widen the filters).' : 'No enabled LLM rule.'}</Typography>}
            {rows.length > 0 && (
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            {HEAD.map(([label, tip], i) => (
                                <TableCell key={i}>{tip ? <Tooltip title={tip}><span style={{ cursor: 'help', borderBottom: '1px dotted' }}>{label}</span></Tooltip> : label}</TableCell>
                            ))}
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {rows.slice(0, RULE_ROWS_MAX).map(r => (
                            <TableRow key={r.rule_id}>
                                <TableCell><Link to={studio(r.rule_id, 'health')}>{r.rule_name}</Link>{r.enabled === false ? ' (disabled)' : ''}</TableCell>
                                <TableCell><HealthChip health={r.health} /></TableCell>
                                <TableCell>{r.qa.last_30d.samples ? `${fmtPct(r.qa.last_30d.agreement)} of ${r.qa.last_30d.samples}` : '-'}</TableCell>
                                <TableCell>{fmtPct(r.escalation_rate)}</TableCell>
                                <TableCell>{r.harness_decisions ? <Link to={listUrl('hits', { rule_id: r.rule_id, decided_tier: 'harness', presence: 'all', view: 'list' })}>{fmtNum(r.harness_decisions)}</Link> : 0}</TableCell>
                                <TableCell>{r.questions_open ? <Link to={review('questions', { rule_id: r.rule_id })}>{fmtNum(r.questions_open)}</Link> : 0}</TableCell>
                                <TableCell>{fmtNum(r.escalation_pending ?? r.backlog)}</TableCell>
                                <TableCell>{r.needs_improvement
                                    ? <Button component={Link} to={studio(r.rule_id, 'mislabeled')} size="small">Improve prompt</Button> : null}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            )}
            <TruncatedNote shown={Math.min(rows.length, RULE_ROWS_MAX)} total={rows.length} what="rules" hint="search to find the rest" />
            <Typography variant="caption" color="text.secondary">
                A rule needs improvement below {fmtPct(quality.agreement_min)} agreement with at least {quality.min_samples} samples in 30 days.
                {' '}<AsOf value={quality.computed_at} snapshot={quality.snapshot} />
            </Typography>
        </Stack>
    );
};

// ---- Proposals ---------------------------------------------------------------------------------------------------------

const verdictLabel = m => { const v = trialVerdict(m); return v && typeof v === 'object' ? v.label : v; };

const Proposals = ({ data }) => (
    <Stack spacing={1}>
        <SimpleTable rows={data.items} rowKey={p => p.id}
                     empty="No proposals. A harness makes one after a prompt trial (Rule studio ▸ Trials)." columns={[
                         { label: 'Rule', render: p => <Link to={studio(p.rule_id, 'proposals')}>{p.rule_name}</Link> },
                         { label: 'Proposal', render: p => `#${p.id}${p.stale ? ' · rule changed since' : ''}` },
                         { label: 'By', render: p => <span title={fmtDate(p.created_at)}>{p.created_by} · {fmtAgo(p.created_at)}</span> },
                         { label: 'Trial', render: p => (p.trial ? (
                             <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap>
                                 <TrialMetricChips metrics={p.trial.metrics} />
                                 <Typography variant="caption">{verdictLabel(p.trial.metrics)}</Typography>
                             </Stack>) : '-') },
                         { label: '', render: p => <Button component={Link} to={studio(p.rule_id, 'proposals')} size="small">Review</Button> },
                     ]} />
        {data.truncated && <Typography variant="caption" color="text.secondary">Only the first {RULES_MAX} rules were asked.</Typography>}
    </Stack>
);

// ---- Coverage ------------------------------------------------------------------------------------------------------

const Coverage = ({ llm }) => (
    <Stack spacing={1}>
        {llm.rules.length === 0 && <Typography variant="body2" color="text.secondary">No LLM rule is enabled</Typography>}
        {llm.rules.map(r => (
            <Box key={r.id}>
                <Typography variant="body2">
                    <Link to={studio(r.id, 'definition')}>{r.name}</Link>{' '}
                    <Typography component="span" variant="caption" color="text.secondary">
                        v{r.version}, {r.target}: {fmtNum(r.projects_current)} of {fmtNum(r.projects)} projects up to date
                        {r.pending_external ? `, ${r.pending_external} held by a run answered by a harness` : ''}{r.failed ? `, ${r.failed} failed` : ''}
                    </Typography>
                </Typography>
                <CountBar done={r.answered} total={r.total} label="objects judged by the service model" />
            </Box>
        ))}
        <Typography variant="caption" color="text.secondary">
            {fmtNum(llm.main.current)} of {fmtNum(llm.main.projects)} projects have up-to-date verdicts of every rule
            {llm.last_computed_at ? ` · counted ${fmtDate(llm.last_computed_at)}` : ''} · <Link to="/pipeline">Pipeline health</Link>
        </Typography>
    </Stack>
);

export const WorkDesk = () => {
    const dataProvider = useDataProvider();
    const { scope } = useScope();
    const [since] = useState(() => new Date(Date.now() - DAY_MS).toISOString());
    const queues = useQueues(scope);
    const quality = useSnapshot('/llm_quality', {}, []);
    const llm = useSnapshot('/llm_progress', { projects: false }, []);
    const proposals = useOpenProposals();
    const rollouts = useFetch(() => dataProvider.rollouts({ status: 'running' }), []);
    const rolloutsDone = useFetch(() => dataProvider.rollouts({ status: 'done', limit: 50 }), []);
    const clusters = useFetch(() => dataProvider.hitsClusters({ by: 'schema', filter: TODECIDE, limit: CLUSTERS_TOP }), [scope]);
    const matches = useFetch(() => dataProvider.hitsAggregate({ by: ['status'], filter: { status: 'match', presence: 'all', first_seen_after: since } })
        .then(({ data }) => ({ data: data.total || 0 })), [scope]);
    return (
        <Box p={2}>
            <Title title={scopedTitle('Work desk', scope)} />
            <Typography variant="h5" mb={2}>Work desk{scope ? <Typography component="span" variant="h6" color="text.secondary"> · {scope}</Typography> : ''}</Typography>
            <Today queues={queues} quality={quality} proposals={proposals} rollouts={rollouts} clusters={clusters} />
            <Grid container spacing={2} sx={{ mt: 1 }}>
                <Panel title={`Clusters to decide (top ${CLUSTERS_TOP}, same schema across services)`} md={12}>
                    <ClustersToDecide clusters={clusters} />
                </Panel>
                <Panel title="Open hits by rule" md={7}>
                    <Loaded state={queues}>{d => <OpenByRule queues={d} />}</Loaded>
                </Panel>
                <Panel title="New in 24 h" md={5}>
                    <NewIn24h matches={matches} since={since} quality={quality} proposals={proposals} rolloutsDone={rolloutsDone} />
                </Panel>
                <Panel title={<span id="health">Rule health: service model vs harness model</span>} md={12}>
                    <Loaded state={quality}>{q => <RuleHealthTable quality={q} />}</Loaded>
                </Panel>
                <Panel title={<span id="proposals">Prompt proposals waiting for you</span>} md={12}>
                    <Loaded state={proposals}>{p => <Proposals data={p} />}</Loaded>
                </Panel>
                <Grid item xs={12}>
                    <Loaded state={llm}>
                        {d => (
                            <DetailsSection title="Coverage of the LLM rules" count={`${fmtNum(d.main.current)} / ${fmtNum(d.main.projects)} up to date`}>
                                <Coverage llm={d} />
                            </DetailsSection>
                        )}
                    </Loaded>
                </Grid>
            </Grid>
        </Box>
    );
};
