import React, { useState } from 'react';
import { Button, Link, Title, useDataProvider, useNotify } from 'react-admin';
import { Alert, Box, Chip, Grid, IconButton, Stack, Tooltip, Typography } from '@mui/material';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import RefreshIcon from '@mui/icons-material/Refresh';
import {
    AsOf, Clipped, DetailsSection, Loaded, Panel, SimpleTable, StatTile, fmtAgo, fmtDate, fmtDuration, fmtNum, listUrl,
    pluralize, showUrl, useAutoRefresh, useFetch, useSnapshot,
} from './common';
import {
    SCHEDULED_KINDS, jobKindLabel, jobKindStage, jobStageLabel, kindOrder, openQueueFilter, queueCounts, queueFilter,
} from './choices';
import { LlmCoverage, LlmRuns, ParseScans, RuleRollouts } from './Dashboard';
import { useScope } from './scope';

// Admin home: is the pipeline (GitLab sync -> parse -> service model -> harness model -> human) keeping up, what
// is stuck, what to press? Sources: the statistics snapshots GET /jobs/health, GET /scan_progress, GET /llm_progress,
// GET /llm_quality (ETag: a poll costs nothing until the scanner's next refresh; "updated N s ago"), GET /llm_work/stats,
// GET /jobs/errors, GET /llm_rollouts, one GET /hits/aggregate (the review queues). Every panel loads on its own: a
// failing endpoint blanks only its panel.

const H = 3600;
const STALE_PENDING_S = 6 * H;
const STUCK_RUNNING_S = 3 * H;
const LEVELS = ['ok', 'info', 'warning', 'error'];
const LABELS = { ok: 'Keeping up', info: 'Catching up', warning: 'Needs attention', error: 'Falling behind' };
const SENTENCES = {
    ok: 'Nothing waits longer than usual.', info: 'Work is queued and moving.',
    warning: 'Something needs a look.', error: 'The pipeline is falling behind.',
};
const QUESTIONS_URL = listUrl('hits', queueFilter('questions'));
// the API's caps of the lists the next actions act on (GET /scan_progress / /llm_progress limit, job ids per error)
const ACTION_BATCH = 200;
const RETRY_BATCH = 50;

const scheduledKind = kind => SCHEDULED_KINDS.includes(kind);

const kindRows = health => Object.entries(health.kinds).map(([kind, k]) => ({ kind, ...k }))
    .sort((a, b) => kindOrder(a.kind) - kindOrder(b.kind));

// pending jobs that count as "waiting": not a scheduled kind, and not scheduled for later (kinds[k].scheduled)
const scheduledCount = k => (k.scheduled ? k.scheduled.count || 0 : (scheduledKind(k.kind) ? k.pending || 0 : 0));
const waitingOf = k => Math.max(0, (k.pending || 0) - scheduledCount(k));
const waitingAge = (kind, k) => {
    if (scheduledKind(kind)) return null;
    if (k.scheduled && k.scheduled.count >= (k.pending || 0)) return null;
    return k.oldest_pending_s;
};
const scheduledOf = health => kindRows(health).reduce((acc, k) => {
    const count = scheduledCount(k);
    const next = k.scheduled ? k.scheduled.next_run_in_s : null;
    return { count: acc.count + (count || 0), next_s: next === null || next === undefined ? acc.next_s : Math.min(acc.next_s ?? Infinity, next) };
}, { count: 0, next_s: null });

const lastDoneAt = health => kindRows(health).map(k => k.last_done_at).filter(Boolean).sort().pop() || null;
// ETA of a kind's waiting jobs at the rate of the last hour (kinds[k].eta_s from the API, else computed)
const etaOf = k => (k.eta_s !== null && k.eta_s !== undefined ? k.eta_s : (k.done_1h ? (waitingOf(k) / k.done_1h) * H : null));
const rateLine = k => (k.done_1h ? `${etaOf(k) !== null ? `~${fmtDuration(etaOf(k))} @ ` : ''}${fmtNum(k.done_1h)}/h` : '');

// ---- verdict (sec. 4.1): each reason is one line with a link ----------------------------------------------------

export const verdict = ({ health, scan, llm, work, quality, errors }) => {
    const reasons = [];
    let level = 'ok';
    const worse = (to, text, link) => { reasons.push({ text, to: link }); if (LEVELS.indexOf(to) > LEVELS.indexOf(level)) level = to; };
    if (!health) return { level, label: LABELS[level], reasons, scheduled: { count: 0, next_s: null } };
    const rows = kindRows(health);
    const totals = health.totals;

    if (totals.failed_24h > 0) {
        const top = errors && errors.items && errors.items[0];
        worse('warning', `${pluralize(totals.failed_24h, 'job')} failed in 24 h${top ? ` (${top.error_prefix} ×${top.count})` : ''}`,
              listUrl('jobs', { status: 'failed' }));
    }
    const failedMain = (scan && scan.main.failed) || 0;
    const failedLlm = (llm && llm.main.failed) || 0;
    if (failedMain > 0) worse('error', `${failedMain} main ${failedMain === 1 ? 'branch' : 'branches'} ended failed`, listUrl('jobs', { kind: 'scan_branch', status: 'failed' }));
    if (failedLlm > 0) worse('error', `${pluralize(failedLlm, 'LLM run')} ended failed`, listUrl('jobs', { kind: 'llm_score', status: 'failed' }));

    const oldest = rows.map(k => ({ k, age: waitingAge(k.kind, k) })).filter(x => x.age !== null && x.age !== undefined)
        .sort((a, b) => b.age - a.age)[0];
    if (oldest && oldest.age > STALE_PENDING_S) {
        worse('error', `${jobKindLabel(oldest.k.kind)} #${oldest.k.oldest_pending_job} waits for ${fmtDuration(oldest.age)}`,
              showUrl('jobs', oldest.k.oldest_pending_job));
    }
    rows.filter(k => k.longest_running_s > Math.max(STUCK_RUNNING_S, 5 * (k.typical_run_s || 0))).forEach(k => worse('warning',
        `${jobKindLabel(k.kind)} #${k.longest_running_job} runs for ${fmtDuration(k.longest_running_s)}${k.typical_run_s ? ` (usually ${fmtDuration(k.typical_run_s)})` : ''}`,
        showUrl('jobs', k.longest_running_job)));

    const scanWait = rows.filter(k => ['scan_branch', 'scan_mr'].includes(k.kind) && waitingOf(k) > 0 && k.eta_s > 24 * H);
    scanWait.forEach(k => worse('warning', `${pluralize(waitingOf(k), 'parse job')} waiting (${jobKindLabel(k.kind)}), ~${fmtDuration(k.eta_s)} at ${k.done_1h}/h`,
                                listUrl('jobs', { kind: k.kind, status: 'pending' })));
    if (health.llm.eta_s !== null && health.llm.eta_s > 24 * H) {
        worse('warning', `${pluralize(health.llm.pending_runs, 'LLM run')} waiting, ~${fmtDuration(health.llm.eta_s)} at ${fmtNum(health.llm.objects_per_hour)} objects/h`,
              listUrl('jobs', { kind: 'llm_score', status: 'pending' }));
    }
    if (health.llm.pending_runs > 0 && health.llm.objects_per_hour === 0 && health.llm.running_runs === 0) {
        worse('error', 'LLM runs wait but no LLM worker processed anything for 1 h', listUrl('jobs', { kind: 'llm_score', status: 'pending' }));
    }
    if (work) {
        const checks = (work.by_purpose.verify || {}).pending || 0;
        const runItems = (work.by_purpose.score || {}).pending || 0;
        const oldestItem = Math.max((work.by_purpose.verify || {}).oldest_pending_s || 0, (work.by_purpose.score || {}).oldest_pending_s || 0);
        const answered1h = work.owners_24h.some(o => o.answered_1h > 0);
        const last = work.owners_24h.map(o => o.last_answer_at).filter(Boolean).sort().pop();
        // a fresh check with an idle harness is normal (harnesses poll); an hour without an answer is not
        if (checks + runItems > 0 && oldestItem > H && !answered1h) {
            const what = [checks && pluralize(checks, 'check'), runItems && pluralize(runItems, 'run item')].filter(Boolean).join(' and ');
            worse('warning', `${what} wait for a harness; ${last ? `last answer ${fmtAgo(last)}` : 'no harness answered in 24 h'}`, '/harness');
        }
    }
    if (quality) {
        const q = quality.totals;
        if (q.questions_open > 0) {
            const text = `${pluralize(q.questions_open, 'question')} wait for a human${q.oldest_question_s ? ` (oldest ${fmtDuration(q.oldest_question_s)})` : ''}`;
            if (q.oldest_question_s > 24 * H) worse('warning', text, QUESTIONS_URL);
            else reasons.push({ text, to: QUESTIONS_URL });     // a note: a human answers within a day
        }
    }
    // the daily escalation cap (LLM_ESCALATION_DAILY_MAX per rule): the overflow stays decided by the service model
    const esc = health.escalations;
    if (esc && esc.overflow_today > 0) {
        reasons.push({ text: `${pluralize(esc.overflow_today, 'unsure verdict')} over the daily escalation cap (${fmtNum(esc.daily_max)} per rule) stay service-decided today`,
                       to: listUrl('hits', queueFilter('unsure')) });
    }
    // a queue that clears within an hour is "keeping up"; a longer one is "catching up" (info)
    const waiting = rows.reduce((n, k) => n + waitingOf(k), 0);
    if (waiting > 0) {
        const etas = rows.filter(k => waitingOf(k) > 0).map(etaOf).filter(e => e !== null);
        const slow = rows.some(k => waitingOf(k) > 0 && ((etaOf(k) ?? Infinity) > H || (waitingAge(k.kind, k) || 0) > H));
        if (level === 'ok' && slow) level = 'info';
        reasons.push({ text: `${pluralize(waiting, 'job')} queued and moving${etas.length ? `: ~${fmtDuration(Math.max(...etas))}` : ''}`,
                       to: listUrl('jobs', { status: ['pending', 'running'] }) });
    }
    return { level, label: LABELS[level], reasons, scheduled: scheduledOf(health) };
};

const Headline = ({ data, onRefresh }) => {
    const v = verdict(data);
    const s = v.scheduled;
    return (
        <Alert severity={v.level === 'ok' ? 'success' : v.level} sx={{ mb: 2, '& .MuiAlert-message': { width: '100%' } }}
               action={<Button label="Refresh" onClick={onRefresh} startIcon={<RefreshIcon />} />}>
            <Typography variant="h6">{v.label}</Typography>
            <Typography variant="body2">
                {SENTENCES[v.level]}
                {s.count > 0 && ` ${pluralize(s.count, 'scheduled job')}${s.next_s !== null ? `, next in ${fmtDuration(s.next_s)}` : ''}.`}
            </Typography>
            {v.reasons.length > 0 && (
                <Typography variant="body2" component="ul" sx={{ m: 0, pl: 2, mt: 0.5 }}>
                    {v.reasons.map(r => <li key={r.text}>{r.to ? <Link to={r.to}>{r.text}</Link> : r.text}</li>)}
                </Typography>
            )}
        </Alert>
    );
};

// ---- stage tiles (sec. 4.2) ------------------------------------------------------------------------------------

const TileLink = ({ to, label }) => <Link to={to} variant="caption">→ {label}</Link>;
const idleSince = k => `idle since ${k && k.last_done_at ? fmtDate(k.last_done_at) : '-'}`;
const sumWaiting = (health, kinds) => kinds.reduce((n, kind) => n + waitingOf(health.kinds[kind] || {}), 0);
const sumFailed = (health, kinds) => kinds.reduce((n, kind) => n + ((health.kinds[kind] || {}).failed_24h || 0), 0);

const Tiles = ({ health, scan, llm, work, quality, queues }) => {
    const k = health.kinds;
    const syncKinds = ['sync_projects', 'sync_branches_mrs'];
    const parseKinds = ['scan_branch', 'scan_mr', 'ingest'];
    const syncWaiting = sumWaiting(health, syncKinds);
    const syncNext = (k.sync_projects && k.sync_projects.scheduled && k.sync_projects.scheduled.next_run_in_s) ?? null;
    const parseWaiting = sumWaiting(health, parseKinds);
    const parseRate = parseKinds.map(kind => k[kind]).filter(x => x && waitingOf(x) > 0).map(rateLine).filter(Boolean)[0];
    // scans of the last 24 h the diff-based skip ended without a clone (no parser file changed) vs full ones
    const scans = health.scans;
    const scansFull = scans ? (scans.scan_branch.full || 0) + (scans.scan_mr.full || 0) : 0;
    const scansSkipped = scans ? (scans.scan_branch.skipped || 0) + (scans.scan_mr.skipped || 0) : 0;
    const scansLine = scansFull + scansSkipped > 0 ? `24 h: ${fmtNum(scansFull)} full, ${fmtNum(scansSkipped)} skipped scans` : null;
    const mrs = scan && scan.mrs;
    const mrLine = !mrs ? '-' : mrs.active_24h !== undefined
        ? `MRs active 24 h: ${mrs.active_scanned || 0} of ${mrs.active_24h}${mrs.active_waiting ? ` (${mrs.active_waiting} waiting)` : ''}`
        : `MRs: ${mrs.scanned_current} of ${mrs.open} open (idle MRs are not scanned by policy)`;

    const llmRate = health.llm;
    const llmBusy = llmRate.pending_runs + llmRate.running_runs > 0;
    const llmLine = llmBusy ? `${fmtNum(llmRate.objects_per_hour)} objects/h${llmRate.eta_s !== null ? `, ~${fmtDuration(llmRate.eta_s)}` : ''}` : idleSince(k.llm_score);

    const owners = (work && work.owners_24h) || [];
    const leases = (work && work.leases) || [];
    const lastAnswer = owners.map(o => o.last_answer_at).filter(Boolean).sort().pop();
    const openChecks = work ? (work.by_purpose.verify.open || 0) + (work.by_purpose.score.open || 0) : 0;
    const recent = lastAnswer && Date.now() - new Date(lastAnswer).getTime() < H * 1000;
    const harnessState = !work ? '-' : owners.length === 0 ? 'no harness in 24 h'
        : (recent || leases.length ? `connected${lastAnswer ? ` ${fmtAgo(lastAnswer)}` : ''}` : `last seen ${fmtAgo(lastAnswer)}`);
    const oldestCheck = work && work.by_purpose.verify.oldest_pending_s;
    const esc = health.escalations;
    const escLine = esc ? `escalations today: ${fmtNum(esc.items_today)}${esc.overflow_today ? `, ${fmtNum(esc.overflow_today)} over the cap` : ''} (cap ${fmtNum(esc.daily_max)}/rule)` : null;

    const q = quality && quality.totals;
    const qc = queues || null;
    return (
        <Box sx={{ display: 'grid', gap: 2, mb: 2, gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: 'repeat(5, 1fr)' } }}>
            <StatTile title="GitLab sync" level={sumFailed(health, syncKinds) ? 'warning' : (syncWaiting ? 'info' : 'ok')}
                      value={scan ? `${fmtNum(scan.main.synced)} / ${fmtNum(scan.main.projects)}` : '-'}
                      sub1={scan && scan.last_projects_sync ? `last sync ${fmtDate(scan.last_projects_sync.finished_at || scan.last_projects_sync.created_at)}` : 'projects synced'}
                      sub2={syncWaiting ? `${pluralize(syncWaiting, 'sync job')} waiting` : (syncNext !== null ? `next in ${fmtDuration(syncNext)}` : idleSince(k.sync_branches_mrs || k.sync_projects))}
                      to={listUrl('jobs', { kind: syncKinds })} action={<TileLink to={listUrl('jobs', { kind: syncKinds })} label="Jobs" />} />
            <StatTile title="Parse" level={sumFailed(health, parseKinds) || (scan && scan.main.failed) ? 'error' : (parseWaiting ? 'info' : 'ok')}
                      value={scan ? `${fmtNum(scan.main.scanned_current)} / ${fmtNum(scan.main.projects)} main` : '-'}
                      sub1={mrLine} sub2={parseWaiting ? (parseRate || `${pluralize(parseWaiting, 'parse job')} waiting`) : (scansLine || idleSince(k.scan_mr || k.scan_branch))}
                      to={listUrl('jobs', { kind: 'scan_mr' })} action={<TileLink to={listUrl('jobs', { kind: 'scan_mr' })} label="MR parse jobs" />} />
            <StatTile title="Service model" level={llm && llm.main.failed ? 'error' : (llmBusy ? 'info' : 'ok')}
                      value={llm ? `${fmtNum(llm.main.answered)} / ${fmtNum(llm.main.total)}` : '-'}
                      sub1="objects judged" sub2={llmLine}
                      to={listUrl('jobs', { kind: ['llm_score', 'llm_prepare', 'llm_apply', 'llm_verify'] })}
                      action={<TileLink to={listUrl('jobs', { kind: ['llm_score', 'llm_prepare', 'llm_apply', 'llm_verify'] })} label="Rule runs" />} />
            <StatTile title="Harness model" level={!work ? 'ok' : (openChecks > 0 && oldestCheck > H && !recent && !leases.length ? 'warning' : (esc && esc.overflow_today ? 'info' : 'ok'))}
                      value={work ? `${pluralize(openChecks, 'check')} open` : '-'}
                      sub1={openChecks && oldestCheck !== null && oldestCheck !== undefined ? `oldest ${fmtDuration(oldestCheck)} · ${harnessState}` : harnessState}
                      sub2={escLine || (lastAnswer ? `last answer ${fmtDate(lastAnswer)}` : 'no answer in 24 h')}
                      to="/harness" action={<TileLink to="/harness" label="Harness work" />} />
            <StatTile title="Human" level={q && q.questions_open > 0 && q.oldest_question_s > 24 * H ? 'warning' : 'ok'}
                      value={qc ? pluralize(qc.questions, 'waiting question') : (q ? pluralize(q.questions_open, 'waiting question') : '-')}
                      sub1={q && q.oldest_question_s !== undefined && q.oldest_question_s !== null ? `oldest ${fmtDuration(q.oldest_question_s)}` : 'asked by the harness model'}
                      sub2={qc ? `pending review ${fmtNum(qc.pending)} · model unsure ${fmtNum(qc.unsure)}` : 'pending review: -'}
                      to={listUrl('hits', openQueueFilter())} action={<TileLink to={listUrl('hits', openQueueFilter())} label="Review" />} />
        </Box>
    );
};

// ---- next actions (sec. 4.3): buttons only when there is something to do ---------------------------------------

const NextActions = ({ health, scan, llm, quality, errors, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const [busy, setBusy] = useState(false);
    const fail = e => notify(e.message || 'Request failed', { type: 'error' });
    const run = fn => { setBusy(true); fn().catch(fail).finally(() => { setBusy(false); onDone(); }); };

    const behind = scan ? (scan.main.outdated || 0) + (scan.main.never_scanned || 0) : 0;
    const uncovered = llm ? (llm.main.never || 0) + (llm.main.outdated || 0) : 0;
    const failed = (health && health.totals.failed_24h) || 0;
    const failedIds = errors ? [...new Set((errors.items || []).flatMap(e => e.job_ids || []))].slice(0, RETRY_BATCH) : [];
    const takeOver = (health && health.llm.pending_runs) || 0;
    const questions = (quality && quality.totals.questions_open) || 0;
    // the actions work on the first ACTION_BATCH projects the API lists: the label says so when there are more
    const batch = n => (n > ACTION_BATCH ? `first ${ACTION_BATCH} of ${fmtNum(n)}` : fmtNum(n));

    const parseBehind = () => run(() => dataProvider.scanProgress({ status: 'outdated,never_scanned', limit: ACTION_BATCH }).then(({ data }) => {
        const ids = data.projects.items.map(p => p.project_id);
        if (!ids.length || !window.confirm(`Queue ${pluralize(ids.length, 'parse job')}${data.projects.total > ids.length ? ` (${fmtNum(data.projects.total - ids.length)} more stay behind: press again later)` : ''}?`)) return null;
        return dataProvider.parse('projects', { data: { project_ids: ids, mains: true, mrs: false } })
            .then(({ data: r }) => notify(`${pluralize(r.queued.length, 'parse job')} queued${r.already_queued.length ? `, ${r.already_queued.length} already queued` : ''}`, { type: 'info' }));
    }));
    const runRules = () => run(() => dataProvider.llmProgress({ status: 'never,outdated', limit: ACTION_BATCH }).then(({ data }) => {
        const ids = data.projects.items.map(p => p.project_id);
        const ruleIds = (llm.rules || []).map(r => r.id);
        if (!ids.length || !ruleIds.length || !window.confirm(`Run ${pluralize(ruleIds.length, 'LLM rule')} on ${pluralize(ids.length, 'project')}${data.projects.total > ids.length ? ` (${fmtNum(data.projects.total - ids.length)} more later)` : ''}?`)) return null;
        return dataProvider.runRules('llm_rules', { data: { rule_ids: ruleIds, project_ids: ids } })
            .then(() => notify(`LLM runs queued for ${pluralize(ids.length, 'project')}`, { type: 'info' }));
    }));
    const retryFailed = () => run(() => Promise.all(failedIds.map(id => dataProvider.retryJob({ id })))
        .then(r => notify(`${pluralize(r.length, 'job')} queued again`, { type: 'info' })));

    const buttons = [
        behind > 0 && <Button key="parse" label={`Parse ${batch(behind)} behind`} variant="outlined" onClick={parseBehind} disabled={busy} />,
        uncovered > 0 && <Button key="rules" label={`Run rules on ${batch(uncovered)} projects`} variant="outlined" onClick={runRules} disabled={busy} />,
        failed > 0 && failedIds.length > 0 && <Button key="retry" label={`Retry ${failed > failedIds.length ? `first ${failedIds.length} of ${fmtNum(failed)}` : fmtNum(failed)} failed`} variant="outlined" onClick={retryFailed} disabled={busy} />,
        takeOver > 0 && <Button key="takeover" label={`Take over ${pluralize(takeOver, 'waiting run')}`} variant="outlined" component={Link} to="/harness" />,
        questions > 0 && <Button key="questions" label={`Answer ${pluralize(questions, 'question')}`} variant="outlined" component={Link} to={QUESTIONS_URL} />,
    ].filter(Boolean);
    return (
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 2 }}>
            <Typography variant="subtitle2">Next actions:</Typography>
            {buttons.length ? buttons : <Typography variant="body2" color="text.secondary">nothing to do</Typography>}
        </Stack>
    );
};

// ---- the one queue table (sec. 4.4) ----------------------------------------------------------------------------

// age chip colour relative to the usual wait of the kind in the last 24 h (fallback: fixed 2 h / 6 h)
const ageColor = (seconds, typical) => {
    if (seconds > STALE_PENDING_S) return 'error';
    if (typical) return seconds > 10 * typical ? 'error' : (seconds > 3 * typical ? 'warning' : 'default');
    return seconds > 2 * H ? 'warning' : 'default';
};
const ageChip = (seconds, typical) => <Chip size="small" label={fmtDuration(seconds)} color={ageColor(seconds, typical)} />;

// a kind with nothing waiting, running, retrying or failed in 24 h is idle: collapsed behind "N idle kinds"
const idleKind = k => !waitingOf(k) && !k.running && !k.retrying && !k.failed_24h && !(k.scheduled && k.scheduled.count);

const Queue = ({ health }) => {
    const [showIdle, setShowIdle] = useState(false);
    const all = kindRows(health);
    const idle = all.filter(idleKind);
    const rows = showIdle ? all : all.filter(k => !idleKind(k));
    const anyWaiting = rows.some(k => waitingOf(k) > 0);
    let lastStage = null;
    const columns = [
        { label: 'Stage', render: r => { const s = jobKindStage(r.kind); const show = s !== lastStage; lastStage = s; return show && s ? jobStageLabel(s) : ''; } },
        { label: 'Kind', render: r => <Link to={listUrl('jobs', { kind: r.kind })}>{jobKindLabel(r.kind)}</Link> },
        { label: 'Waiting', render: r => (waitingOf(r) ? <Link to={listUrl('jobs', { kind: r.kind, status: 'pending' })}>{waitingOf(r)}</Link> : 0) },
        { label: 'Retrying', render: r => (r.retrying ? <Chip size="small" color="warning" label={r.retrying} /> : 0) },
        { label: 'Running', render: r => (r.running ? <Link to={listUrl('jobs', { kind: r.kind, status: 'running' })}>{r.running}</Link> : 0) },
        { label: 'Done 1h / 24h', render: r => `${r.done_1h} / ${r.done_24h}${r.skipped_24h ? ` (${r.skipped_24h} skipped)` : ''}` },
        { label: 'Failed 24h', render: r => (r.failed_24h ? <Link to={listUrl('jobs', { kind: r.kind, status: 'failed' })}><Chip size="small" color="error" label={r.failed_24h} /></Link> : 0) },
        { label: 'Oldest waiting', render: r => {
            const scheduled = r.scheduled && r.scheduled.count > 0 ? r.scheduled : (scheduledKind(r.kind) && r.pending ? { count: r.pending } : null);
            const age = waitingAge(r.kind, r);
            if (age !== null && age !== undefined && r.oldest_pending_job) {
                return <Link to={showUrl('jobs', r.oldest_pending_job)}>{ageChip(age, r.typical_wait_s)}</Link>;
            }
            if (scheduled) return scheduled.next_run_in_s !== undefined && scheduled.next_run_in_s !== null ? `next run in ${fmtDuration(scheduled.next_run_in_s)}` : 'scheduled';
            return '-';
        } },
        { label: 'Longest running', render: r => (r.longest_running_job
            ? <Link to={showUrl('jobs', r.longest_running_job)}>{ageChip(r.longest_running_s, r.typical_run_s ? r.typical_run_s * 1.5 : null)}</Link> : '-') },
        ...(anyWaiting ? [{ label: 'Throughput / ETA', render: r => (waitingOf(r) > 0 ? rateLine(r) || '-' : '') }] : []),
        { label: 'Typical run / wait', render: r => (r.typical_run_s || r.typical_wait_s
            ? `${r.typical_run_s ? fmtDuration(r.typical_run_s) : '-'} / ${r.typical_wait_s ? fmtDuration(r.typical_wait_s) : '-'}` : '') },
    ];
    return (
        <Stack spacing={1}>
            <SimpleTable rows={rows} rowKey={r => r.kind} empty={all.length ? 'Every kind is idle' : 'No jobs yet'} columns={columns} />
            {idle.length > 0 && (
                <Typography variant="caption" color="text.secondary">
                    {pluralize(idle.length, 'idle kind')} ({idle.map(k => jobKindLabel(k.kind)).join(', ')}){' '}
                    <Link to="#" onClick={e => { e.preventDefault(); setShowIdle(!showIdle); }}>{showIdle ? 'hide' : 'show'}</Link>
                </Typography>
            )}
        </Stack>
    );
};

const QueueLegend = () => (
    <Tooltip title="Oldest waiting: orange when a job waits more than 3 times the usual wait of its kind in the last 24 h, red above 10 times or 6 h (typical run / wait: medians of the last 24 h from jobs.started_at). ETA: the backlog at the last hour's rate, else the typical run time x backlog / busy workers. Scheduled kinds (cleanup, rollout slices, statistics) show their next run instead. Done 24h (N skipped): scans ended by the diff-based skip - no parser file changed since the snapshot, nothing cloned or parsed. Kinds with nothing waiting, running or failed are collapsed.">
        <IconButton size="small" aria-label="Legend"><InfoOutlinedIcon fontSize="small" /></IconButton>
    </Tooltip>
);

// ---- workers (sec. 4.5) ----------------------------------------------------------------------------------------

const Workers = ({ health }) => {
    const waiting = kindRows(health).reduce((n, k) => n + waitingOf(k), 0);
    const last = lastDoneAt(health);
    const quiet = !last || Date.now() - new Date(last).getTime() > 2 * H * 1000;
    return (
        <Stack spacing={1}>
            {health.workers.length > 0 && (
                <SimpleTable rows={health.workers} rowKey={w => w.job_id} columns={[
                    { label: 'Worker', render: w => w.locked_by || '-' },
                    { label: 'Job', render: w => <Link to={showUrl('jobs', w.job_id)}>{jobKindLabel(w.kind)} #{w.job_id}</Link> },
                    { label: 'For', render: w => fmtDuration(w.since_s) },
                    { label: 'Progress', render: w => (w.progress ? [w.progress.phase,
                        w.progress.total_objects !== undefined && `${w.progress.done_objects || 0} of ${w.progress.total_objects} objects`,
                        w.progress.objects !== undefined && `${w.progress.objects} objects`].filter(Boolean).join(' · ') : '-') },
                ]} />
            )}
            {waiting > 0 && quiet && health.workers.length === 0 ? (
                <Alert severity="warning">{pluralize(waiting, 'job')} wait, nothing finished in 2 h: are the workers alive?</Alert>
            ) : (
                <Typography variant="body2" color="text.secondary">
                    {health.workers.length ? 'No other worker is busy' : 'No worker is busy'} · last job finished {last ? fmtDate(last) : '-'}
                </Typography>
            )}
            {health.limits && (
                <Typography variant="caption" color="text.secondary">
                    Pools: scan {health.limits.scan_workers} · sync {health.limits.sync_workers} · control {health.limits.control_workers} · LLM {health.limits.llm_workers}
                    {' '}× {health.limits.llm_concurrency} calls{health.limits.llm_rate_per_min ? ` · ${fmtNum(health.limits.llm_rate_per_min)} calls/min (${fmtNum(health.limits.llm_rate_tokens_left)} left)` : ' · no rate limit'}
                    {' '}· escalation cap {fmtNum(health.limits.escalation_daily_max)}/rule/day
                </Typography>
            )}
        </Stack>
    );
};

// ---- failures of the last 24 h (sec. 4.6, GET /jobs/errors) -----------------------------------------------------

const Failures = ({ errors, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const [busy, setBusy] = useState(false);
    const retry = ids => {
        setBusy(true);
        Promise.all(ids.slice(0, 50).map(id => dataProvider.retryJob({ id })))
            .then(r => notify(`${pluralize(r.length, 'job')} queued again`, { type: 'info' }))
            .catch(e => notify(e.message || 'Retry failed', { type: 'error' }))
            .finally(() => { setBusy(false); onDone(); });
    };
    return (
        <SimpleTable rows={errors.items} rowKey={r => `${r.kind}:${r.error_prefix}`} empty="No failed job in 24 h" columns={[
            { label: 'Kind', render: r => jobKindLabel(r.kind) },
            { label: 'Cause', render: r => <Clipped text={r.error_prefix} max={140} /> },
            { label: 'Count', render: r => r.count },
            { label: 'First / last seen', render: r => `${fmtAgo(r.first_seen_at)} / ${fmtAgo(r.last_seen_at)}` },
            { label: 'Sample', render: r => (r.sample_job_id ? <Link to={showUrl('jobs', r.sample_job_id)}>#{r.sample_job_id}</Link> : '-') },
            { label: '', render: r => <Button size="small" label={`Retry all ${r.count}`} disabled={busy || !(r.job_ids || []).length} onClick={() => retry(r.job_ids)} /> },
        ]} />
    );
};

// ---- page ------------------------------------------------------------------------------------------------------

export const PipelineHealth = () => {
    const dataProvider = useDataProvider();
    const { scope } = useScope();
    const health = useSnapshot('/jobs/health', {}, []);
    const scan = useSnapshot('/scan_progress', { projects: false }, []);
    const llm = useSnapshot('/llm_progress', { projects: false }, []);
    const work = useFetch(() => dataProvider.llmWorkStats(), []);
    const quality = useSnapshot('/llm_quality', {}, []);
    const errors = useFetch(() => dataProvider.jobErrors({ hours: 24 }), []);
    const rollouts = useFetch(() => dataProvider.rollouts({ limit: 50 }), []);
    // the review queues (questions / pending / unsure) from one aggregate: the same numbers as Review and the Work desk
    const queues = useFetch(() => dataProvider.hitsAggregate({ by: ['queue'], filter: { field_marks: false } })
        .then(({ data }) => ({ data: queueCounts(data.rows) })), [scope]);
    const all = [health, scan, llm, work, quality, errors, rollouts, queues];
    // the snapshots answer 304 until the scanner refreshes them: polling every 15 s is cheap; the hook waits for the
    // previous round, slows down in a hidden tab and backs off on errors
    const reloadAll = () => Promise.all(all.map(s => s.reload())).then(r => r.every(Boolean));
    const active = !!(health.data && (health.data.totals.pending + health.data.totals.running) > 0);
    useAutoRefresh(active, reloadAll, 15000);

    const data = { health: health.data, scan: scan.data, llm: llm.data, work: work.data, quality: quality.data, errors: errors.data };
    const behind = scan.data ? (scan.data.main.outdated || 0) + (scan.data.main.never_scanned || 0) : null;
    const openRollouts = rollouts.data ? rollouts.data.items.filter(r => ['planned', 'running', 'paused'].includes(r.status)).length : null;
    const activeRuns = health.data ? health.data.llm.pending_runs + health.data.llm.running_runs : null;
    const n = v => (v === null || v === undefined ? '…' : fmtNum(v));
    return (
        <Box p={2}>
            <Title title="Pipeline health" />
            <Box display="flex" alignItems="center" gap={1} mb={2} flexWrap="wrap">
                <Typography variant="h5">Pipeline health</Typography>
                <Typography variant="caption" color="text.secondary">
                    sync → parse → service model → harness model → human
                </Typography>
                {health.data && <AsOf value={health.computedAt || health.data.now} snapshot={health.snapshot} />}
                <Tooltip title="The verdict uses the current queue, the age of the oldest waiting job, the usual wait and run time of each kind in the last 24 h, the hourly rate and the failures of the last 24 h (GET /jobs/health, MCP job_health), from the scanner's statistics snapshot (refreshed every minute; 'live' when the snapshot is stale).">
                    <IconButton size="small" aria-label="How the verdict is computed"><InfoOutlinedIcon fontSize="small" /></IconButton>
                </Tooltip>
            </Box>
            <Loaded state={health}>
                {() => (
                    <>
                        <Headline data={data} onRefresh={reloadAll} />
                        <Tiles {...data} queues={queues.data} />
                        <NextActions {...data} onDone={reloadAll} />
                    </>
                )}
            </Loaded>
            <Grid container spacing={2}>
                <Panel title="Job queue" md={12} action={<QueueLegend />}>
                    <Loaded state={health}>{h => <Box sx={{ overflowX: 'auto' }}><Queue health={h} /></Box>}</Loaded>
                </Panel>
                <Panel title="Workers" md={6}>
                    <Loaded state={health}>{h => <Workers health={h} />}</Loaded>
                </Panel>
                <Panel title="Failures (24 h)" md={6}>
                    <Loaded state={errors}>{e => <Failures errors={e} onDone={reloadAll} />}</Loaded>
                </Panel>
            </Grid>
            <Box mt={2}>
                <DetailsSection title="Parse details" count={`${n(behind)} behind, ${n(scan.data && scan.data.main.failed)} failed`}>
                    <ParseScans />
                </DetailsSection>
                <DetailsSection title="LLM coverage" count={`${n(llm.data && llm.data.main.current)} / ${n(llm.data && llm.data.main.projects)} up to date`}>
                    <LlmCoverage />
                </DetailsSection>
                <DetailsSection title="Rule runs" count={`${n(activeRuns)} active`}>
                    <LlmRuns />
                </DetailsSection>
                <DetailsSection title="Rollouts" count={openRollouts ? `${openRollouts} open` : 'none open'}>
                    <RuleRollouts />
                </DetailsSection>
            </Box>
        </Box>
    );
};
