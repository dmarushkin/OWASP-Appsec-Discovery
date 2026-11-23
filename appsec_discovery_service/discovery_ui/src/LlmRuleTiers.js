import React, { useEffect, useState } from 'react';
import { Button, Link, useDataProvider, useNotify, useRecordContext, useRefresh } from 'react-admin';
import { useLocation } from 'react-router-dom';
import {
    Alert, Box, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, Tab, Tabs,
    TextField as MuiTextField, ToggleButton, ToggleButtonGroup, Tooltip, Typography,
} from '@mui/material';
import {
    Clipped, DetailsSection, HealthChip, Loaded, RunProgress, SimpleTable, StatusChip, TrialMetricChips, fmtAgo, fmtDate,
    fmtPct, listUrl, showUrl, trialVerdict, useAutoRefresh, useFetch,
} from './common';
import {
    proposalStatusLabel, statusLabel, trialStatusLabel, versionSourceLabel, versionStatusLabel,
} from './choices';
import { RuleRollouts } from './Dashboard';

// Rule studio of an LLM rule (tabs of the edit page): Definition (the form), Versions (GET /llm_rules/{id}/versions:
// diff, cost, activate / rollback by a human; the rollout of the active one), Health & quality (GET /llm_quality),
// Mislabelled (GET /llm_rules/{id}/mislabeled: where a human or the harness model disagreed with the service model),
// Trials (GET/POST /llm_rules/{id}/trials: a candidate prompt run by the service model, no hits written), Proposals
// (GET /llm_rules/{id}/proposals: a human accepts or rejects) and Runs (GET /llm_runs filtered by the rule).

const agreementText = a => (a && a.samples ? `${fmtPct(a.agreement)} of ${a.samples}` : '-');
const subjectOf = i => `${i.object_name || i.object_key}${i.field_name ? '.' + i.field_name : ''}`;
const verdictLabel = m => { const v = trialVerdict(m); return v && typeof v === 'object' ? v.label : v; };

const TrialResult = ({ metrics }) => (metrics ? (
    <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap>
        <TrialMetricChips metrics={metrics} />
        <Typography variant="caption">{verdictLabel(metrics)}</Typography>
    </Stack>
) : <span>-</span>);

const Pre = ({ children }) => (
    <Box component="pre" sx={{ whiteSpace: 'pre-wrap', fontSize: 12, m: 0, p: 1, bgcolor: 'action.hover' }}>{children}</Box>
);

// ---- Health & quality --------------------------------------------------------------------------------------------

const METRIC_TIPS = {
    all: 'QA sample: confident service verdicts the harness model re-checked; agreement = share it confirmed',
    week: 'The same, last 7 days',
    match: 'Agreement on the service model\'s "match" verdicts: low means false positives of the service model',
    no_match: 'Agreement on the service model\'s "no match" verdicts: low means false negatives of the service model',
    unsure: 'QA samples the harness model could not decide either',
    escalation: 'Share of the service model\'s current verdicts that were "needs more info"; every one is a check for the harness model',
    escalations: 'Escalations of the last 30 days, and how many the harness model decided',
    harness: 'Hits whose current decision is the harness model\'s',
    questions: 'Open questions the harness model asked a human about this rule',
    backlog: 'Checks waiting for a harness model',
    verified: 'When the harness model last answered a check of this rule',
};

const Metric = ({ tip, children }) => (
    <Tooltip title={tip || ''}><span style={{ cursor: tip ? 'help' : 'default', borderBottom: tip ? '1px dotted' : 'none' }}>{children}</span></Tooltip>
);

const RuleHealth = ({ ruleId }) => {
    const dataProvider = useDataProvider();
    const quality = useFetch(() => dataProvider.llmQuality({ ruleId }), [ruleId]);
    return (
        <Loaded state={quality}>
            {data => {
                const r = data.rules[0];
                if (!r) return <Typography variant="body2">No data</Typography>;
                const rows = [
                    { k: 'Agreement, all time', tip: METRIC_TIPS.all, v: agreementText(r.qa) },
                    { k: 'Agreement, last 7 days', tip: METRIC_TIPS.week, v: agreementText(r.qa.last_7d) },
                    { k: 'Agreement on "match" verdicts', tip: METRIC_TIPS.match, v: agreementText(r.qa.by_verdict.match) },
                    { k: 'Agreement on "no match" verdicts', tip: METRIC_TIPS.no_match, v: agreementText(r.qa.by_verdict.no_match) },
                    { k: 'Harness model unsure on the QA sample', tip: METRIC_TIPS.unsure, v: r.qa.unsure },
                    { k: 'Escalation rate', tip: METRIC_TIPS.escalation, v: fmtPct(r.escalation_rate) },
                    { k: 'Escalations, last 30 days (decided by the harness model)', tip: METRIC_TIPS.escalations, v: `${r.escalations_30d} (${r.escalations_decided_30d})` },
                    { k: 'Decisions of the harness model', tip: METRIC_TIPS.harness,
                      v: <Link to={listUrl('hits', { rule_id: ruleId, decided_tier: 'harness', presence: 'all' })}>{r.harness_decisions}</Link> },
                    { k: 'Open questions for a human', tip: METRIC_TIPS.questions, v: r.questions_open
                        ? <Link to={listUrl('hits', { asked_by_model: true, status: 'need_more_info', rule_id: ruleId })}>{r.questions_open}</Link>
                        : 0 },
                    { k: 'Checks queued for the harness model', tip: METRIC_TIPS.backlog, v: r.escalation_pending ?? r.backlog },
                    { k: 'Last check answered', tip: METRIC_TIPS.verified, v: r.last_verified_at ? <span title={fmtDate(r.last_verified_at)}>{fmtAgo(r.last_verified_at)}</span> : '-' },
                ];
                return (
                    <Stack spacing={1}>
                        <Box display="flex" gap={1} alignItems="center" flexWrap="wrap">
                            <HealthChip health={r.health} />
                            <Typography variant="body2">
                                Agreement of the service model with the harness model on the QA sample, last 30 days:{' '}
                                <b>{agreementText(r.qa.last_30d)}</b> (threshold {fmtPct(data.agreement_min)}, at least{' '}
                                {data.min_samples} samples)
                            </Typography>
                        </Box>
                        <SimpleTable rows={rows} rowKey={x => x.k} columns={[
                            { label: 'Metric', render: x => <Metric tip={x.tip}>{x.k}</Metric> },
                            { label: 'Value', render: x => x.v },
                        ]} />
                        {r.needs_improvement && (
                            <Alert severity="warning">
                                The harness model disagrees with the service model too often: see Mislabelled; try a prompt in Trials.
                            </Alert>
                        )}
                    </Stack>
                );
            }}
        </Loaded>
    );
};

// ---- Mislabelled -------------------------------------------------------------------------------------------------

const trialSnippet = (ruleId, source) => `llm_mislabeled(rule_id=${ruleId}, source="${source}")
llm_prompt_trial(rule_id=${ruleId}, prompt="<candidate system prompt>", from_mislabeled=true, include_controls=20, rerun_current=true)
llm_prompt_trial_result(trial_id=<id>, only="wrong")
propose_prompt_change(rule_id=${ruleId}, prompt="<the same text>", trial_id=<id>, rationale="...")`;

const useCopy = () => {
    const notify = useNotify();
    return text => navigator.clipboard && navigator.clipboard.writeText(text)
        .then(() => notify('Copied', { type: 'info' }), () => notify('Copy failed', { type: 'warning' }));
};

const Mislabeled = ({ ruleId }) => {
    const dataProvider = useDataProvider();
    const copy = useCopy();
    const [source, setSource] = useState('verification');
    const state = useFetch(() => dataProvider.mislabeled({ ruleId, source }), [ruleId, source]);
    return (
        <Stack spacing={1}>
            <Box display="flex" gap={2} alignItems="center" flexWrap="wrap">
                <ToggleButtonGroup size="small" exclusive value={source} onChange={(e, v) => v && setSource(v)}>
                    <ToggleButton value="verification">Harness model disagreed</ToggleButton>
                    <ToggleButton value="human">Human disagreed</ToggleButton>
                </ToggleButtonGroup>
                <Typography variant="body2" color="text.secondary">
                    Objects / fields where the {source === 'human' ? 'human' : 'harness model'} decided differently from the service
                    model: the targets of a prompt trial. "Trial-ready" = still in a current snapshot and in the rule's scope.
                </Typography>
            </Box>
            <Loaded state={state}>
                {d => (
                    <>
                        <Typography variant="body2">{d.total} disagreement(s) (showing {d.items.length})</Typography>
                        <SimpleTable rows={d.items} rowKey={i => i.hit_id} empty="No disagreement" columns={[
                            { label: 'Subject', render: i => <Link to={showUrl('hits', i.hit_id)}>{subjectOf(i)}</Link> },
                            { label: 'Project', source: 'project_path' },
                            { label: 'Service model said', render: i => (
                                <Stack direction="row" spacing={0.5} alignItems="center">
                                    {i.machine_verdict ? <StatusChip status={i.machine_verdict} /> : '?'}
                                    <Typography variant="caption"><Clipped text={i.machine_reason || ''} max={120} /></Typography>
                                </Stack>) },
                            { label: source === 'human' ? 'Human said' : 'Harness model said', render: i => (
                                <Stack direction="row" spacing={0.5} alignItems="center">
                                    <StatusChip status={i.expected_verdict} />
                                    <Typography variant="caption">{i.reviewer || i.verifier_model || ''}</Typography>
                                </Stack>) },
                            { label: 'Note', render: i => <Clipped text={i.note || ''} max={120} /> },
                            { label: 'Trial-ready', render: i => (i.trial_ready ? 'yes' : (i.problem || 'no')) },
                        ]} />
                    </>
                )}
            </Loaded>
            <DetailsSection title="For a harness">
                <Typography variant="body2" color="text.secondary" gutterBottom>
                    A harness model can improve the prompt from these with MCP; you accept or reject its proposal in Proposals.
                </Typography>
                <Pre>{trialSnippet(ruleId, source)}</Pre>
                <Button label="Copy" size="small" onClick={() => copy(trialSnippet(ruleId, source))} />
            </DetailsSection>
        </Stack>
    );
};

// ---- Trials ------------------------------------------------------------------------------------------------------

const TrialDialog = ({ id, onClose }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.trial({ id }), [id]);
    const [only, setOnly] = useState('all');
    const filterItems = items => (only === 'all' ? items
        : items.filter(i => (only === 'wrong' ? i.new.verdict !== i.expected
            : i.new.verdict !== ((i.rerun && i.rerun.verdict) || i.current.verdict))));
    return (
        <Dialog open onClose={onClose} fullWidth maxWidth="lg" aria-labelledby="trial-title">
            <DialogTitle id="trial-title">Prompt trial #{id}</DialogTitle>
            <DialogContent>
                <Loaded state={state}>
                    {t => (
                        <Stack spacing={1}>
                            <Box display="flex" gap={1} alignItems="center" flexWrap="wrap">
                                <Chip size="small" label={trialStatusLabel(t.status)} color={t.status === 'failed' ? 'error' : 'default'} variant="outlined" />
                                <Typography variant="body2">
                                    model {t.model || '-'} · {t.calls} of {t.planned_calls} calls{t.failed_calls ? ` (${t.failed_calls} failed)` : ''}
                                </Typography>
                                <TrialResult metrics={t.metrics} />
                            </Box>
                            {t.error && <Alert severity="error">{t.error}</Alert>}
                            <Typography variant="subtitle2">Candidate prompt</Typography>
                            <Pre>{t.candidate_prompt}</Pre>
                            <ToggleButtonGroup size="small" exclusive value={only} onChange={(e, v) => v && setOnly(v)}>
                                <ToggleButton value="all">All subjects</ToggleButton>
                                <ToggleButton value="changed">Changed</ToggleButton>
                                <ToggleButton value="wrong">Still wrong</ToggleButton>
                            </ToggleButtonGroup>
                            <SimpleTable rows={filterItems(t.items)} rowKey={i => i.subject_key} empty="Nothing in this view" columns={[
                                { label: 'Role', source: 'role' },
                                { label: 'Subject', render: i => subjectOf(i) },
                                { label: 'Expected', render: i => (i.expected ? statusLabel(i.expected) : '-') },
                                { label: 'Current (stored)', render: i => (i.current.verdict ? statusLabel(i.current.verdict) : '-') },
                                { label: 'Current (re-run)', render: i => (i.rerun && i.rerun.verdict ? statusLabel(i.rerun.verdict) : '-') },
                                { label: 'Candidate', render: i => (i.new.verdict ? statusLabel(i.new.verdict) : (i.asked ? 'failed' : 'pending')) },
                                { label: 'Candidate reason', render: i => i.new.reason || i.error || '' },
                            ]} />
                        </Stack>
                    )}
                </Loaded>
            </DialogContent>
            <DialogActions><Button label="Close" onClick={onClose} /></DialogActions>
        </Dialog>
    );
};

const mcpTrialSnippet = (ruleId, d) => `llm_prompt_trial(rule_id=${ruleId}, prompt="<the prompt>", from_mislabeled=${d.from_mislabeled ? 'true' : 'false'}, include_controls=${d.include_controls}${d.sample ? `, sample=${d.sample}` : ''}, rerun_current=true)`;

// "Try this prompt": POST /llm_rules/{id}/trials through dataProvider.createTrial (exported by the shared data
// provider); without it the dialog shows the MCP call for a harness.
const TryPromptDialog = ({ ruleId, initialPrompt, initial = {}, onClose, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const copy = useCopy();
    const [prompt, setPrompt] = useState(initialPrompt || '');
    const [useSample, setUseSample] = useState(initial.sample !== undefined ? !!initial.sample : true);
    const [sample, setSample] = useState(initial.sample || 20);
    const [mislabeled, setMislabeled] = useState(initial.from_mislabeled !== undefined ? !!initial.from_mislabeled : false);
    const [useControls, setUseControls] = useState(initial.include_controls !== undefined ? !!initial.include_controls : true);
    const [controls, setControls] = useState(initial.include_controls || 20);
    const [busy, setBusy] = useState(false);
    const canPost = typeof dataProvider.createTrial === 'function';
    const data = {
        prompt, from_mislabeled: mislabeled, include_controls: useControls ? Number(controls) || 0 : 0, rerun_current: true,
        ...(useSample && Number(sample) > 0 ? { sample: Number(sample) } : {}),
    };
    const valid = prompt.trim() && (data.sample || data.from_mislabeled);
    const submit = () => {
        setBusy(true);
        dataProvider.createTrial({ ruleId, data })
            .then(({ data: t }) => { notify(`Trial #${t.id} queued`, { type: 'info' }); onDone(); })
            .catch(e => notify(e.message || 'Trial failed', { type: 'error' }))
            .finally(() => setBusy(false));
    };
    return (
        <Dialog open onClose={onClose} fullWidth maxWidth="md" aria-labelledby="try-title">
            <DialogTitle id="try-title">Try this prompt</DialogTitle>
            <DialogContent>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                    The service model answers the candidate prompt on a few objects; nothing is written to the hits. The result
                    compares it with the current verdicts.
                </Typography>
                <MuiTextField label="Candidate system prompt" value={prompt} onChange={e => setPrompt(e.target.value)} fullWidth
                              multiline minRows={8} margin="dense" />
                <Typography variant="subtitle2" sx={{ mt: 1 }}>Objects to judge</Typography>
                <Box display="flex" alignItems="center" gap={1} flexWrap="wrap">
                    <FormControlLabel control={<Checkbox checked={useSample} onChange={e => setUseSample(e.target.checked)} />}
                                      label="random objects in scope:" />
                    <MuiTextField type="number" size="small" value={sample} onChange={e => setSample(e.target.value)} disabled={!useSample}
                                  inputProps={{ min: 1, max: 200 }} sx={{ width: 90 }} />
                </Box>
                <FormControlLabel control={<Checkbox checked={mislabeled} onChange={e => setMislabeled(e.target.checked)} />}
                                  label="mislabelled subjects (where a human or the harness model disagreed with the service model)" />
                <Box display="flex" alignItems="center" gap={1} flexWrap="wrap">
                    <FormControlLabel control={<Checkbox checked={useControls} onChange={e => setUseControls(e.target.checked)} />}
                                      label="controls (agreed verdicts that should not change):" />
                    <MuiTextField type="number" size="small" value={controls} onChange={e => setControls(e.target.value)} disabled={!useControls}
                                  inputProps={{ min: 0, max: 1000 }} sx={{ width: 90 }} />
                </Box>
                {!canPost && (
                    <Alert severity="info" sx={{ mt: 1 }}>
                        This UI build cannot start a trial itself. Ask a harness with MCP:
                        <Pre>{mcpTrialSnippet(ruleId, data)}</Pre>
                        <Button label="Copy" size="small" onClick={() => copy(mcpTrialSnippet(ruleId, data))} />
                    </Alert>
                )}
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                {canPost && <Button label="Start the trial" variant="contained" onClick={submit} disabled={busy || !valid} />}
            </DialogActions>
        </Dialog>
    );
};

const TrialsPanel = ({ ruleId, prompt }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.trials({ ruleId }), [ruleId]);
    const [open, setOpen] = useState(null);
    const [tryIt, setTryIt] = useState(false);
    const active = !!(state.data && state.data.items.some(t => t.status === 'queued' || t.status === 'running'));
    useAutoRefresh(active, state.reload, 5000);
    return (
        <Loaded state={state}>
            {data => (
                <Stack spacing={1}>
                    <Box display="flex" gap={2} alignItems="center" flexWrap="wrap">
                        <Button label="Try this prompt" variant="contained" onClick={() => setTryIt(true)} />
                        <Typography variant="body2" color="text.secondary">
                            Budget today: {data.budget.used_today} of {data.budget.daily_calls} service model calls.
                        </Typography>
                    </Box>
                    <SimpleTable rows={data.items} rowKey={t => t.id}
                                 empty="No trial yet. Try a prompt here, or let a harness do it (Harness work ▸ How to connect)." columns={[
                                     { label: 'Trial', render: t => <Button label={`#${t.id}`} onClick={() => setOpen(t.id)} /> },
                                     { label: 'Status', render: t => (
                                         <Stack direction="row" spacing={0.5} alignItems="center">
                                             <Chip size="small" variant="outlined" label={trialStatusLabel(t.status)} color={t.status === 'failed' ? 'error' : 'default'} />
                                             {t.stale && <Chip size="small" variant="outlined" label="rule changed since" />}
                                         </Stack>) },
                                     { label: 'By', source: 'created_by' },
                                     { label: 'Calls', render: t => `${t.calls} / ${t.planned_calls}` },
                                     { label: 'Result', render: t => <TrialResult metrics={t.metrics} /> },
                                     { label: 'Created', render: t => <span title={fmtDate(t.created_at)}>{fmtAgo(t.created_at)}</span> },
                                 ]} />
                    {open && <TrialDialog id={open} onClose={() => setOpen(null)} />}
                    {tryIt && <TryPromptDialog ruleId={ruleId} initialPrompt={prompt} onClose={() => setTryIt(false)}
                                               onDone={() => { setTryIt(false); state.reload(); }} />}
                </Stack>
            )}
        </Loaded>
    );
};

// ---- Proposals ---------------------------------------------------------------------------------------------------

// Accepting a proposal is a human decision: accept and roll out (the new version is active at once), or accept as a
// candidate only (activate it later in Versions).
const DecideDialog = ({ proposal, accept, outdated, onClose, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const cost = useFetch(() => (accept ? dataProvider.proposalReask({ id: proposal.id }) : Promise.resolve({ data: null })),
                          [proposal.id, accept]);
    const [note, setNote] = useState(outdated ? 'Outdated: the rule changed since the trial.' : '');
    const [busy, setBusy] = useState(false);
    const submit = activate => {
        setBusy(true);
        const call = accept ? dataProvider.acceptProposal : dataProvider.rejectProposal;
        call({ id: proposal.id, data: accept ? { note: note || null, activate } : { note: note || null } })
            .then(({ data }) => {
                notify(accept ? (activate ? `Proposal accepted: v${data.version.version} is active, its rollout runs`
                    : `Proposal accepted: candidate v${data.version.version} (activate it in Versions)`) : 'Proposal rejected',
                { type: 'info' });
                onDone();
            })
            .catch(error => notify(error.message || 'Failed', { type: 'error' }))
            .finally(() => setBusy(false));
    };
    return (
        <Dialog open onClose={onClose} fullWidth maxWidth="md" aria-labelledby="decide-title">
            <DialogTitle id="decide-title">{accept ? 'Accept' : 'Reject'} prompt proposal #{proposal.id}</DialogTitle>
            <DialogContent>
                {accept && (
                    <Loaded state={cost}>
                        {c => c && (
                            <Alert severity="info" sx={{ mb: 1 }}>
                                Once active, the rollout asks the service model again about{' '}
                                {(c.migration || {}).subjects ?? c.subjects_to_send} verdicts ({(c.migration || {}).model_calls ?? c.model_calls} model
                                calls, in budgeted slices){c.fresh ? `, plus ${c.fresh.model_calls} calls for fresh objects` : ''}
                                {c.truncated ? ' (estimate truncated)' : ''}. Human and harness-model decisions are kept.
                            </Alert>
                        )}
                    </Loaded>
                )}
                <MuiTextField label="Note" value={note} onChange={e => setNote(e.target.value)} fullWidth margin="dense" />
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                {accept ? (
                    <>
                        <Button label="Accept as candidate only" onClick={() => submit(false)} disabled={busy || cost.loading} />
                        <Button label="Accept and roll out" variant="contained" onClick={() => submit(true)} disabled={busy || cost.loading} />
                    </>
                ) : <Button label={outdated ? 'Reject as outdated' : 'Reject'} variant="contained" onClick={() => submit(false)} disabled={busy} />}
            </DialogActions>
        </Dialog>
    );
};

// re-ask cost of an open proposal (GET /prompt_proposals/{id}/reask), loaded at once
const ReaskCost = ({ proposalId }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.proposalReask({ id: proposalId }), [proposalId]);
    if (state.error) return <Typography variant="caption" color="error">{state.error.message}</Typography>;
    if (!state.data) return <Typography variant="caption" color="text.secondary">estimating the re-ask cost…</Typography>;
    const c = state.data;
    return (
        <Typography variant="body2">
            Re-ask on accept: <b>{(c.migration || {}).model_calls ?? c.model_calls}</b> model calls over{' '}
            {(c.migration || {}).subjects ?? c.subjects_to_send} objects{c.truncated ? ' (estimate truncated)' : ''}; human and
            harness decisions are kept.
        </Typography>
    );
};

const ProposalsPanel = ({ ruleId, onChanged }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.proposals({ ruleId }), [ruleId]);
    const [decide, setDecide] = useState(null);
    const [rerun, setRerun] = useState(null);
    return (
        <Loaded state={state}>
            {data => (
                <Stack spacing={2}>
                    {!data.items.length && (
                        <Typography variant="body2" color="text.secondary">
                            No proposals. A harness makes one after a prompt trial (see Mislabelled ▸ For a harness).
                        </Typography>
                    )}
                    {data.items.map(p => (
                        <Box key={p.id} sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 1 }}>
                            <Box display="flex" gap={1} alignItems="center" flexWrap="wrap">
                                <Typography variant="subtitle2">#{p.id}</Typography>
                                <Chip size="small" variant="outlined" label={proposalStatusLabel(p.status)} color={p.status === 'open' ? 'primary' : 'default'} />
                                {p.stale && <Tooltip title={`Made on v${p.base_version}; the rule is at v${p.current_version} now. Re-run the trial before accepting.`}><Chip size="small" color="warning" variant="outlined" label="rule changed since" /></Tooltip>}
                                <Typography variant="body2">
                                    by {p.created_by} · <span title={fmtDate(p.created_at)}>{fmtAgo(p.created_at)}</span> · based on v{p.base_version} · trial #{p.trial.id}
                                </Typography>
                                <TrialResult metrics={p.trial.metrics} />
                            </Box>
                            <Typography variant="body2" sx={{ mt: 1, whiteSpace: 'pre-wrap' }}>{p.rationale}</Typography>
                            <DiffBlock diff={p.diff} />
                            {p.decided_by && (
                                <Typography variant="caption">{proposalStatusLabel(p.status)} by {p.decided_by} {fmtDate(p.decided_at)}{p.decision_note ? `: ${p.decision_note}` : ''}{p.accepted_version ? ` → v${p.accepted_version}` : ''}</Typography>
                            )}
                            {p.status === 'open' && !p.stale && (
                                <Box mt={1} display="flex" gap={1} alignItems="center" flexWrap="wrap">
                                    <Button label="Accept…" variant="contained" onClick={() => setDecide({ p, accept: true })} />
                                    <Button label="Reject…" onClick={() => setDecide({ p, accept: false })} />
                                    <ReaskCost proposalId={p.id} />
                                </Box>
                            )}
                            {p.status === 'open' && p.stale && (
                                <Box mt={1} display="flex" gap={1} alignItems="center" flexWrap="wrap">
                                    <Button label="Re-run the trial on the current version" variant="contained" onClick={() => setRerun(p)} />
                                    <Button label="Reject as outdated" onClick={() => setDecide({ p, accept: false, outdated: true })} />
                                </Box>
                            )}
                        </Box>
                    ))}
                    {decide && <DecideDialog proposal={decide.p} accept={decide.accept} outdated={decide.outdated} onClose={() => setDecide(null)}
                                             onDone={() => { setDecide(null); state.reload(); if (onChanged) onChanged(); }} />}
                    {rerun && <TryPromptDialog ruleId={ruleId} initialPrompt={rerun.prompt} initial={{ from_mislabeled: true, include_controls: 20, sample: 0 }}
                                               onClose={() => setRerun(null)} onDone={() => { setRerun(null); if (onChanged) onChanged(); }} />}
                </Stack>
            )}
        </Loaded>
    );
};

// ---- Versions ----------------------------------------------------------------------------------------------------

const VERSION_COLORS = { active: 'success', candidate: 'primary' };

export const DiffBlock = ({ diff }) => (diff ? (
    <Box component="pre" sx={{ whiteSpace: 'pre-wrap', fontSize: 12, bgcolor: 'action.hover', p: 1, mt: 1, mb: 0 }}>
        {diff.split('\n').map((line, i) => (
            <Box key={i} component="span" sx={{ display: 'block',
                color: line.startsWith('+') && !line.startsWith('+++') ? 'success.main'
                    : (line.startsWith('-') && !line.startsWith('---') ? 'error.main' : undefined) }}>{line}</Box>
        ))}
    </Box>
) : null);

// The cost of activating a version (GET /llm_rule_versions/{id}/estimate): no model is called.
export const VersionCost = ({ estimate }) => {
    if (!estimate) return null;
    const m = estimate.migration || {};
    return (
        <Alert severity="info" sx={{ my: 1 }}>
            About <b>{estimate.est_calls}</b> model calls: {(estimate.fresh || {}).model_calls || 0} for fresh objects (the
            normal runs) and <b>{m.model_calls || 0}</b> for the rollout of {m.subjects || 0} older machine verdicts
            ({m.need_more_info || 0} needs-more-info first, {m.positive || 0} match, {m.negative || 0} no match;
            {' '}{m.projects || 0} projects){estimate.same_content ? ' - same prompt and scope: verdicts already made by the new core prompts / model are relabelled' : ''}.
            Kept: {estimate.protected_human} human and {estimate.protected_harness} harness decisions.
            {estimate.truncated ? ' (estimate truncated)' : ''}
        </Alert>
    );
};

const ActivateDialog = ({ version, rollback, onClose, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const estimate = useFetch(() => (rollback ? Promise.resolve({ data: null }) : dataProvider.versionEstimate({ id: version.id })),
                              [version.id, rollback]);
    const [start, setStart] = useState(true);
    const [calls, setCalls] = useState('');
    const [note, setNote] = useState('');
    const [busy, setBusy] = useState(false);
    const submit = () => {
        setBusy(true);
        const data = { start_rollout: start, note: note || null, budget: calls ? { calls_per_hour: Number(calls) } : null };
        (rollback ? dataProvider.rollbackVersion : dataProvider.activateVersion)({ id: version.id, data })
            .then(({ data: r }) => {
                notify(rollback ? `Rolled back: v${r.version.version} active, ${r.adopted || 0} verdicts adopted from the history`
                    : `v${version.version} is active; rollout ${r.rollout.status}`, { type: 'info' });
                onDone();
            })
            .catch(error => notify(error.message || 'Failed', { type: 'error' }))
            .finally(() => setBusy(false));
    };
    return (
        <Dialog open onClose={onClose} fullWidth maxWidth="md" aria-labelledby="activate-title">
            <DialogTitle id="activate-title">{rollback ? `Roll back to the content of v${version.version}` : `Activate v${version.version}`}</DialogTitle>
            <DialogContent>
                {rollback ? (
                    <Alert severity="info">
                        A new version with the prompt and scope of v{version.version} becomes active; the verdicts v{version.version} made on
                        the same content are adopted from the history without model calls, the rest is migrated by a rollout.
                    </Alert>
                ) : <Loaded state={estimate}>{e => <VersionCost estimate={e} />}</Loaded>}
                <FormControlLabel label="Start the rollout now" title="Unchecked: the rollout is planned; start it here or on Pipeline health"
                                  control={<Checkbox checked={start} onChange={e => setStart(e.target.checked)} />} />
                <MuiTextField label="Calls per hour (empty: default)" value={calls} type="number"
                              onChange={e => setCalls(e.target.value)} fullWidth margin="dense" />
                <MuiTextField label="Note" value={note} onChange={e => setNote(e.target.value)} fullWidth margin="dense" />
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                <Button label={rollback ? 'Roll back' : 'Activate'} variant="contained" onClick={submit} disabled={busy || (!rollback && estimate.loading)} />
            </DialogActions>
        </Dialog>
    );
};

const VersionsPanel = ({ ruleId, onChanged }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const state = useFetch(() => dataProvider.ruleVersions({ ruleId }), [ruleId]);
    const [open, setOpen] = useState({});
    const [estimates, setEstimates] = useState({});
    const [dialog, setDialog] = useState(null);
    const estimate = v => dataProvider.versionEstimate({ id: v.id })
        .then(({ data }) => setEstimates(e => ({ ...e, [v.id]: data })))
        .catch(e => notify(e.message || 'Failed', { type: 'error' }));
    const discard = v => dataProvider.discardVersion({ id: v.id, data: {} })
        .then(() => { notify(`v${v.version} discarded`, { type: 'info' }); state.reload(); })
        .catch(e => notify(e.message || 'Failed', { type: 'error' }));
    const done = () => { setDialog(null); state.reload(); if (onChanged) onChanged(); };
    return (
        <Loaded state={state}>
            {data => (
                <Stack spacing={1.5}>
                    <Typography variant="body2" color="text.secondary">
                        Active v{data.rule.version},{' '}
                        <Tooltip title={`core prompts version ${data.rule.core_prompt_version}${data.rule.code_core_prompt_version !== data.rule.core_prompt_version ? ` (the scanner runs ${data.rule.code_core_prompt_version})` : ''}`}><span style={{ borderBottom: '1px dotted' }}>core prompts</span></Tooltip>
                        {' '}· model {data.rule.llm_model || 'not recorded yet'}{data.rule.service_model && data.rule.service_model !== data.rule.llm_model ? ` (the scanner runs ${data.rule.service_model})` : ''}.
                        Verdicts of older versions stay (stale, still scoring) until the rollout of the active version asks them again.
                    </Typography>
                    {data.items.map(v => (
                        <Box key={v.id} sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 1 }}>
                            <Box display="flex" gap={1} alignItems="center" flexWrap="wrap">
                                <Typography variant="subtitle2">v{v.version}</Typography>
                                <Chip size="small" variant="outlined" label={versionStatusLabel(v.status)} color={VERSION_COLORS[v.status] || 'default'} />
                                <Chip size="small" variant="outlined" label={versionSourceLabel(v.source)} />
                                <Typography variant="body2">
                                    model {v.model || '-'} · by {v.created_by || '-'} {fmtDate(v.created_at)}
                                    {v.activated_at ? ` · activated ${fmtDate(v.activated_at)}` : ''}
                                </Typography>
                            </Box>
                            {v.note && <Typography variant="caption" component="div" sx={{ whiteSpace: 'pre-wrap' }}>{v.note}</Typography>}
                            {v.diff && (
                                <Box mt={0.5}>
                                    <Button size="small" label={open[v.id] ? 'Hide diff' : 'Diff to the active version'}
                                            onClick={() => setOpen(o => ({ ...o, [v.id]: !o[v.id] }))} />
                                    {open[v.id] && (
                                        <Box>
                                            <DiffBlock diff={v.diff.prompt} />
                                            {Object.entries(v.diff.matchers || {}).map(([k, [a, b]]) => (
                                                <Typography key={k} variant="body2">{k}: {String(a ?? '-')} → {String(b ?? '-')}</Typography>
                                            ))}
                                            {v.diff.target && <Typography variant="body2">target: {v.diff.target.join(' → ')}</Typography>}
                                            {v.diff.core_prompt_version && <Typography variant="body2">core prompts: {v.diff.core_prompt_version.join(' → ')}</Typography>}
                                            {v.diff.model && <Typography variant="body2">model: {v.diff.model.join(' → ')}</Typography>}
                                            {v.same_content && <Typography variant="caption">Same prompt and scope.</Typography>}
                                        </Box>
                                    )}
                                </Box>
                            )}
                            <VersionCost estimate={estimates[v.id]} />
                            <Box mt={0.5} display="flex" gap={1} flexWrap="wrap">
                                {['candidate', 'draft'].includes(v.status) && (
                                    <>
                                        <Button label="Estimate" size="small" onClick={() => estimate(v)} />
                                        <Button label="Activate…" variant="contained" size="small" onClick={() => setDialog({ v, rollback: false })} />
                                        <Button label="Discard" size="small" onClick={() => discard(v)} />
                                    </>
                                )}
                                {['retired', 'rolled_back'].includes(v.status) && (
                                    <Button label="Roll back to this…" size="small" onClick={() => setDialog({ v, rollback: true })} />
                                )}
                                {v.status === 'active' && <Button label="Rollout cost" size="small" onClick={() => estimate(v)} />}
                            </Box>
                            {v.status === 'active' && (
                                <Box mt={1}>
                                    <Typography variant="subtitle2">Rollout of this version</Typography>
                                    <RuleRollouts ruleId={ruleId} />
                                </Box>
                            )}
                        </Box>
                    ))}
                    {dialog && <ActivateDialog version={dialog.v} rollback={dialog.rollback} onClose={() => setDialog(null)} onDone={done} />}
                </Stack>
            )}
        </Loaded>
    );
};

// ---- Runs --------------------------------------------------------------------------------------------------------

const ofRule = (run, ruleId) => !run.rules || run.rules.some(r => r.id === ruleId);

// GET /llm_rules/{id}/errors: why evaluations of this rule failed in the last week - the failed objects with their
// reason and job (service runs, refused harness answers), the runs that ended failed / incomplete
const RuleErrors = ({ ruleId, tick }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.llmRuleErrors({ ruleId }), [ruleId, tick]);
    const where = r => `${r.project_path || '?'} / ${r.mr_id ? `MR row ${r.mr_id}` : (r.branch_name || '-')}`;
    return (
        <Loaded state={state}>
            {data => {
                const empty = !data.total && !data.items.length && !data.runs.length && !data.work_items.length;
                if (empty) return <Typography variant="body2" color="text.secondary">No failed evaluation of this rule in the last {Math.round(data.hours / 24)} days</Typography>;
                return (
                    <Stack spacing={2}>
                        {data.by_class.length > 0 && (
                            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap alignItems="center">
                                <Typography variant="body2">{data.total} failed evaluation{data.total === 1 ? '' : 's'}:</Typography>
                                {data.by_class.map(c => (
                                    <Tooltip key={c.error_class} title={`${c.count} in ${c.jobs} run${c.jobs === 1 ? '' : 's'}`}>
                                        <Chip size="small" variant="outlined" color="warning" component={Link} clickable
                                              to={showUrl('jobs', c.last_job_id)} label={`${c.error_class} (${c.count})`} />
                                    </Tooltip>
                                ))}
                            </Stack>
                        )}
                        <SimpleTable rows={data.items} rowKey={r => `${r.job_id}:${r.object_key}:${r.error}`} empty="No failed object recorded" columns={[
                            { label: 'Object', render: r => [r.object || r.object_key || r.where || '-', r.field && `.${r.field}`].filter(Boolean).join('') },
                            { label: 'Error', render: r => <Clipped text={r.error} max={160} /> },
                            { label: 'Job', render: r => <Link to={showUrl('jobs', r.job_id)}>#{r.job_id}</Link> },
                            { label: 'When', render: r => fmtAgo(r.at) },
                        ]} />
                        {data.work_items.length > 0 && (
                            <Box>
                                <Typography variant="subtitle2">Answers of a harness model that could not be used</Typography>
                                <SimpleTable rows={data.work_items} rowKey={r => r.id} columns={[
                                    { label: 'Object', render: r => [r.object || r.object_key, r.field && `.${r.field}`].filter(Boolean).join('') },
                                    { label: 'Error', render: r => <Clipped text={r.error} max={160} /> },
                                    { label: 'Harness / model', render: r => [r.answered_by, r.model].filter(Boolean).join(' / ') || '-' },
                                    { label: 'Run', render: r => <Link to={showUrl('jobs', r.job_id)}>#{r.job_id}</Link> },
                                    { label: 'When', render: r => fmtAgo(r.at) },
                                ]} />
                            </Box>
                        )}
                        {data.runs.length > 0 && (
                            <Box>
                                <Typography variant="subtitle2">Runs that ended failed or incomplete</Typography>
                                <SimpleTable rows={data.runs} rowKey={r => r.id} columns={[
                                    { label: 'Job', render: r => <Link to={showUrl('jobs', r.id)}>#{r.id}</Link> },
                                    { label: 'Project / branch', render: where },
                                    { label: 'Status', render: r => [r.status, r.phase && r.phase !== r.status && r.phase].filter(Boolean).join(' · ') },
                                    { label: 'Failed objects', render: r => (r.failed_objects !== null && r.failed_objects !== undefined ? `${r.failed_objects} of ${r.total_objects ?? '?'}` : '-') },
                                    { label: 'Error', render: r => <Clipped text={r.last_error || r.error} max={200} /> },
                                    { label: 'When', render: r => fmtAgo(r.finished_at) },
                                ]} />
                            </Box>
                        )}
                    </Stack>
                );
            }}
        </Loaded>
    );
};

const RunsPanel = ({ ruleId }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.llmRuns(), []);
    const active = !!(state.data && state.data.active.some(r => ofRule(r, ruleId)));
    useAutoRefresh(active, state.reload, 5000);
    const columns = [
        { label: 'Job', render: r => <Link to={showUrl('jobs', r.id)}>{r.id}</Link> },
        { label: 'Purpose', render: r => (r.purpose === 'verify' ? 'Verification (checks for the harness model)' : 'Score run') },
        { label: 'Project / branch', render: r => `${r.project_path || '?'} / ${r.mr_id ? `MR row ${r.mr_id}` : (r.branch_name || r.branch_id || '-')}` },
        { label: 'Answered by', render: r => [r.executor === 'external' ? 'Harness model' : 'Service model', r.taken_over_by && `taken over by ${r.taken_over_by}`].filter(Boolean).join(' · ') },
        { label: 'Status', render: r => [r.status, r.phase === 'incomplete' && 'incomplete'].filter(Boolean).join(' · ') },
        { label: 'Progress', render: r => <RunProgress progress={r} /> },
        { label: 'Error', render: r => ((r.last_error || r.error) ? <Clipped text={r.last_error || r.error} max={120} /> : '-') },
        { label: 'Started', render: r => fmtDate(r.started_at || r.created_at) },
        { label: 'Finished', render: r => fmtDate(r.finished_at) },
    ];
    return (
        <Loaded state={state}>
            {data => (
                <Stack spacing={2}>
                    <Box>
                        <Typography variant="subtitle2">Active (this rule, or runs of all enabled rules)</Typography>
                        <SimpleTable rows={data.active.filter(r => ofRule(r, ruleId))} rowKey={r => r.id} empty="No active run" columns={columns} />
                    </Box>
                    <Box>
                        <Typography variant="subtitle2">Finished in the last 24 hours</Typography>
                        <SimpleTable rows={data.recent.filter(r => ofRule(r, ruleId))} rowKey={r => r.id} empty="None" columns={columns} />
                    </Box>
                    <Box>
                        <Typography variant="subtitle2">Last errors (7 days)</Typography>
                        <RuleErrors ruleId={ruleId} tick={state.data} />
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                        Start a run with the "Run" button above (the service model answers, or a harness model via MCP).
                    </Typography>
                </Stack>
            )}
        </Loaded>
    );
};

// ---- the studio ----------------------------------------------------------------------------------------------------

const TAB_IDS = ['definition', 'versions', 'health', 'mislabeled', 'trials', 'proposals', 'runs'];

const useUrlTab = () => {
    const location = useLocation();
    const fromUrl = () => {
        const wanted = new URLSearchParams(location.search).get('tab');
        return TAB_IDS.includes(wanted) ? wanted : 'definition';
    };
    const [tab, setTab] = useState(fromUrl);
    useEffect(() => { setTab(fromUrl()); }, [location.search]);   // eslint-disable-line react-hooks/exhaustive-deps
    return [tab, setTab];
};

// `form` (the rule form) stays mounted on every tab (hidden), so unsaved edits survive a look at the other tabs.
// A rule that is not enabled yet (just created) gets a banner: try the prompt first, then enable it.
export const RuleStudio = ({ form, aside, actions }) => {
    const record = useRecordContext();
    const refresh = useRefresh();
    const location = useLocation();
    const [tab, setTab] = useUrlTab();
    const [tick, setTick] = useState(0);
    if (!record || !record.id) return form;
    const changed = () => { setTick(t => t + 1); refresh(); };
    const justCreated = new URLSearchParams(location.search).get('created') === '1';
    return (
        <Box>
            {!record.enabled && !record.deleted_at && (
                <Alert severity="info" sx={{ mx: 2, mt: 1 }}>
                    {justCreated ? 'Saved. ' : ''}Not enabled yet. Try the prompt on a sample first (Trials), then enable it in Definition.
                </Alert>
            )}
            <Box display="flex" alignItems="center" gap={1} px={2} pt={1} flexWrap="wrap">
                <Tabs value={tab} onChange={(e, v) => setTab(v)} variant="scrollable" scrollButtons="auto" sx={{ flex: 1 }}>
                    <Tab value="definition" label="Definition" />
                    <Tab value="versions" label="Versions" />
                    <Tab value="health" label="Health & quality" />
                    <Tab value="mislabeled" label="Mislabelled" />
                    <Tab value="trials" label="Trials" />
                    <Tab value="proposals" label="Proposals" />
                    <Tab value="runs" label="Runs" />
                </Tabs>
                {actions}
            </Box>
            <Box sx={{ display: tab === 'definition' ? 'flex' : 'none', alignItems: 'flex-start' }}>
                <Box flex={1} minWidth={0}>{form}</Box>
                {aside}
            </Box>
            <Box p={2} key={tick}>
                {tab === 'versions' && <VersionsPanel ruleId={record.id} onChanged={changed} />}
                {tab === 'health' && <RuleHealth ruleId={record.id} />}
                {tab === 'mislabeled' && <Mislabeled ruleId={record.id} />}
                {tab === 'trials' && <TrialsPanel ruleId={record.id} prompt={record.prompt} />}
                {tab === 'proposals' && <ProposalsPanel ruleId={record.id} onChanged={changed} />}
                {tab === 'runs' && <RunsPanel ruleId={record.id} />}
            </Box>
        </Box>
    );
};
