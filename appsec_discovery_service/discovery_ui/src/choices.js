// The single glossary of the UI (UX v3 sec. 2): every chip, column header, button and toast takes its words from here.
// REST paths, MCP tool names and env names belong in tooltips only.

const labelOf = (map, fallback) => id => (id === null || id === undefined ? (fallback ?? '-') : (map[id] ?? String(id)));
const choicesOf = map => Object.entries(map).map(([id, name]) => ({ id, name }));

// ---------------------------------------------------------------- hits (sec. 2.1)

export const severityChoices = [
    { id: 'critical', name: 'Critical' },
    { id: 'high', name: 'High' },
    { id: 'medium', name: 'Medium' },
    { id: 'low', name: 'Low' },
    { id: 'info', name: 'Info' },
];

// hit statuses are the verdict words (migration 0023); the review actions keep their verbs: confirm -> match,
// reject -> no_match, request_info -> need_more_info, reopen -> pending_review
export const statusChoices = [
    { id: 'pending_review', name: 'Pending review' },
    { id: 'need_more_info', name: 'Needs more info' },
    { id: 'match', name: 'Match' },
    { id: 'no_match', name: 'No match' },
];
const STATUS_NAMES = Object.fromEntries(statusChoices.map(c => [c.id, c.name]));
export const statusLabel = labelOf(STATUS_NAMES);
const STATUS_HINTS = {
    pending_review: 'A review-mode rule hit: waits for a human',
    need_more_info: 'The model was unsure, or asked a human',
    match: 'The rule applies to this object / field',
    no_match: 'The rule does not apply',
};
export const statusHint = id => STATUS_HINTS[id] || '';
// the only coloured chips in the UI (besides failures): green / grey / blue / orange = the hit statuses
export const STATUS_COLORS = { match: 'success', no_match: 'default', need_more_info: 'info', pending_review: 'warning' };

// "Open" = waits for a decision; the one word for it in every counter and link
export const openStatuses = ['pending_review', 'need_more_info'];
export const openFilter = (extra = {}) => ({ status: openStatuses, ...extra });

// The three queues of Review, defined once: the tabs, the menu badge, the Work desk tiles and the Pipeline "Human"
// tile all count the same sets (GET /hits/aggregate?by=queue answers the same keys). A queue hides the field marks
// of object rules (the object hit decides them) and counts live hits (main or an open MR) - the API defaults.
export const QUEUES = {
    questions: { label: 'Questions', filter: { asked_by_model: true, status: 'need_more_info' },
        hint: 'The harness model asked a human about these hits' },
    pending: { label: 'Pending', filter: { status: 'pending_review' },
        hint: 'Hits of review-mode rules: every one waits for a human' },
    unsure: { label: 'Model unsure', filter: { status: 'need_more_info', asked_by_model: false },
        hint: 'The service model was unsure; the harness model checks them when it is connected' },
};
export const QUEUE_IDS = Object.keys(QUEUES);
export const queueLabel = labelOf(Object.fromEntries(QUEUE_IDS.map(id => [id, QUEUES[id].label])));
// the GET /hits filter of one queue (plus extra filters such as rule_id / project_id)
export const queueFilter = (id, extra = {}) => ({ ...QUEUES[id].filter, field_marks: false, ...extra });
// the filter of every open hit of the queues (the badge, "Review N hits" links)
export const openQueueFilter = (extra = {}) => ({ status: openStatuses, field_marks: false, ...extra });
// GET /hits/aggregate?by=queue rows -> { questions, pending, unsure, open } (open = the three queues together)
export const queueCounts = rows => {
    const n = Object.fromEntries(QUEUE_IDS.map(id => [id, 0]));
    (rows || []).forEach(r => { if (r.queue in n) n[r.queue] += Number(r.n) || 0; });
    n.open = QUEUE_IDS.reduce((s, id) => s + n[id], 0);
    return n;
};

// where a hit's code is: in a main branch, only in an open MR (not merged yet), or gone from both
export const presenceOf = hit => (!hit ? null : hit.in_main ? 'main' : (hit.in_open_mr ? 'mr' : 'gone'));
export const presenceLabel = labelOf({ main: 'In main', mr: 'Only in open MR', gone: 'Gone' });
export const presenceHint = labelOf({
    main: 'The object is in a main branch',
    mr: 'The object exists only in an open merge request: not merged yet',
    gone: 'The object is neither in a main branch nor in an open merge request',
}, '');

// review actions named by their result (button / toast); keys in Hits.js: c / r / i / u
export const reviewActionLabels = {
    confirm: 'Mark as match',
    reject: 'Mark as no match',
    request_info: 'Ask for more info',
    reopen: 'Reopen',
};
export const reviewActionToasts = {
    confirm: 'Marked as match',
    reject: 'Marked as no match',
    request_info: 'More info requested',
    reopen: 'Reopened',
};
// client fallback when a row carries no `allowed_actions`: an exact copy of discovery_common REVIEW_TRANSITIONS
export const ALLOWED_ACTIONS = {
    pending_review: ['confirm', 'reject', 'request_info'],
    need_more_info: ['confirm', 'reject', 'reopen'],
    match: ['reopen'],
    no_match: ['reopen'],
};

// who made a hit's current decision (rule_hits.decided_tier)
export const tierChoices = [
    { id: 'service', name: 'Service model' },
    { id: 'harness', name: 'Harness model' },
    { id: 'human', name: 'Human' },
];
export const tierLabel = labelOf(Object.fromEntries(tierChoices.map(c => [c.id, c.name])));
// older name of the same list (Hits.js filter)
export const decidedTierChoices = tierChoices;

// ---------------------------------------------------------------- rules, versions, rollouts (sec. 2.2)

export const modeChoices = [
    { id: 'auto', name: 'Auto (hits match at once; the harness QA-samples them)' },
    { id: 'review', name: 'Review (every hit waits for a human)' },
];
export const modeLabel = labelOf({ auto: 'Auto', review: 'Review' });

export const actionChoices = [
    { id: 'score', name: 'Score' },
    { id: 'exclude', name: 'Exclude (suppress other hits)' },
];

export const targetChoices = [
    { id: 'field', name: 'Field (the model picks matching fields)' },
    { id: 'object', name: 'Object (the model judges the whole object)' },
];
export const targetLabel = labelOf({ field: 'Field', object: 'Object' });

export const healthLabel = labelOf({ ok: 'OK', needs_improvement: 'Needs improvement', not_enough_samples: 'Not enough samples' });
export const HEALTH_COLORS = { ok: 'success', needs_improvement: 'error', not_enough_samples: 'default' };

const VERSION_STATUS = { draft: 'Draft', candidate: 'Candidate', active: 'Active', retired: 'Retired', rolled_back: 'Rolled back' };
export const versionStatusLabel = labelOf(VERSION_STATUS);
export const versionStatusChoices = choicesOf(VERSION_STATUS);
export const versionSourceLabel = labelOf({
    ui: 'Edited in UI', proposal: 'From a proposal', rollback: 'Rollback', core: 'Core prompts change', model: 'Model change',
});

const ROLLOUT_STATUS = { planned: 'Planned', running: 'Running', paused: 'Paused', done: 'Done', cancelled: 'Cancelled' };
export const rolloutStatusLabel = labelOf(ROLLOUT_STATUS);
export const rolloutStatusChoices = choicesOf(ROLLOUT_STATUS);
export const ROLLOUT_COLORS = { planned: 'info', running: 'primary', paused: 'default', done: 'success', cancelled: 'default' };
export const rolloutActionLabel = { start: 'Start', pause: 'Pause', resume: 'Resume', cancel: 'Cancel' };

export const trialStatusLabel = labelOf({ queued: 'Queued', running: 'Running', done: 'Done', failed: 'Failed' });
export const TRIAL_COLORS = { failed: 'error' };
export const proposalStatusLabel = labelOf({ open: 'Open', accepted: 'Accepted', rejected: 'Rejected' });

// who answers an LLM run (jobs.executor / llm_runs)
export const executorLabel = { service: 'Service model', external: 'Harness model' };
// llm_work_items.purpose
export const purposeLabel = { score: 'Score run', verify: 'Verification' };
// llm_work_items.sample (why a verification check exists)
export const sampleLabel = {
    escalation: 'Escalation (service model unsure)',
    qa: 'QA sample (random check)',
    reverify: 'Re-verify (content changed)',
    manual: 'Manual',
};

// ---------------------------------------------------------------- jobs (sec. 2.3)

// discovery_common.models.JOB_KINDS, in pipeline order; `stage` groups the queue table
const JOB_KINDS = [
    ['sync_projects', 'Sync: project list', 'sync'],
    ['sync_branches_mrs', 'Sync: branches and MRs', 'sync'],
    ['scan_branch', 'Parse: main branch', 'parse'],
    ['scan_mr', 'Parse: merge request', 'parse'],
    ['ingest', 'Parse: pushed batch', 'parse'],
    ['llm_score', 'LLM: score run', 'llm'],
    ['llm_prepare', 'LLM: prepare harness run', 'llm'],
    ['llm_apply', 'LLM: apply harness answers', 'llm'],
    ['llm_verify', 'LLM: schedule checks', 'llm'],
    ['llm_coverage', 'LLM: count coverage', 'llm'],
    ['llm_trial', 'LLM: prompt trial', 'lifecycle'],
    ['llm_rollout', 'LLM: rollout slice', 'lifecycle'],
    ['llm_relabel', 'LLM: relabel verdicts', 'lifecycle'],
    ['stats_refresh', 'Housekeeping: statistics snapshot', 'housekeeping'],
    ['cleanup', 'Housekeeping: cleanup', 'housekeeping'],
];
export const jobKindChoices = JOB_KINDS.map(([id, name, stage]) => ({ id, name, stage }));
const KIND_NAMES = Object.fromEntries(JOB_KINDS.map(([id, name]) => [id, name]));
// unknown kinds (a newer scanner) keep their raw id
export const jobKindLabel = labelOf(KIND_NAMES);
export const JOB_STAGES = ['sync', 'parse', 'llm', 'lifecycle', 'housekeeping'];
export const jobStageLabel = labelOf({ sync: 'Sync', parse: 'Parse', llm: 'LLM', lifecycle: 'Lifecycle', housekeeping: 'Housekeeping' });
export const jobKindStage = id => (JOB_KINDS.find(k => k[0] === id) || [])[2] || null;
// table order; unknown kinds sort last
export const KIND_ORDER = Object.fromEntries(JOB_KINDS.map(([id], i) => [id, i]));
export const kindOrder = id => (KIND_ORDER[id] ?? JOB_KINDS.length);
// run on a timer (run_after in the future): their wait does not count as "oldest waiting"
export const SCHEDULED_KINDS = ['cleanup', 'llm_rollout', 'stats_refresh'];

const JOB_STATUS = { pending: 'Waiting', running: 'Running', done: 'Done', failed: 'Failed' };
export const jobStatusChoices = choicesOf(JOB_STATUS);
export const jobStatusLabel = labelOf(JOB_STATUS);
export const JOB_STATUS_COLORS = { failed: 'error', running: 'info' };

// ---------------------------------------------------------------- project states (sec. 2.4)

// parse state of a project's main branch (GET /scan_progress, /projects `scan`); accepts the state object or its id
const SCAN_STATES = {
    current: 'Up to date', outdated: 'Behind', never_scanned: 'Never parsed', partial: 'Partial', failed: 'Failed',
    skipped: 'Skipped', no_main: 'No main branch',
};
const stateId = s => (s && typeof s === 'object' ? s.state : s);
export const scanStateLabel = s => (s ? SCAN_STATES[stateId(s)] || stateId(s) || '-' : '-');
// LLM rule coverage of a project's main branch (GET /llm_progress, /projects `llm`)
const LLM_STATES = { current: 'Up to date', outdated: 'Behind', never: 'Not counted', not_scanned: 'Not parsed', failed: 'Failed' };
export const llmStateLabel = s => (s ? LLM_STATES[stateId(s)] || stateId(s) || '-' : '-');

// ---------------------------------------------------------------- other lists

export const presenceChoices = [
    { id: 'live', name: 'Main or open MRs' },
    { id: 'main', name: 'Main branches' },
    { id: 'mr', name: 'Only in open MRs' },
    { id: 'all', name: 'All (incl. removed code)' },
];
// /objects presence (default main; "all" does not exist there)
export const objectPresenceChoices = presenceChoices.filter(c => c.id !== 'all');

export const kindChoices = [
    { id: 'keyword', name: 'Keyword' },
    { id: 'llm', name: 'LLM' },
];

export const scanModeChoices = [
    { id: 'rules', name: 'Rules (keyword + LLM categorise)' },
    { id: 'inventory', name: 'Inventory (no categorisation, label by hand)' },
];

// the core's parser types (discovery_common.models.PARSER_TYPES)
export const parserChoices = ['client', 'db', 'golang', 'graphql', 'java', 'javascript', 'migrations', 'protobuf',
    'python', 'swagger', 'terraform'];

export const mrStateChoices = [
    { id: 'opened', name: 'Opened' },
    { id: 'merged', name: 'Merged' },
    { id: 'closed', name: 'Closed' },
    { id: 'locked', name: 'Locked' },
];
