import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import {
    List, Datagrid, FunctionField, Link,
    Show, TopToolbar, TextInput, SelectInput, AutocompleteInput, ReferenceInput, DateInput,
    Button, useRecordContext, useDataProvider, useNotify, useRefresh, useListContext,
    useUnselectAll, useRedirect,
} from 'react-admin';
import { useLocation } from 'react-router-dom';
import {
    Alert, Box, Checkbox, Chip, Collapse, Dialog, DialogTitle, DialogContent, DialogActions, FormControlLabel, Grid,
    IconButton, MenuItem, Paper, Skeleton, Snackbar, Stack, Tab, Tabs, Table, TableBody, TableCell, TableHead, TableRow,
    TextField as MuiTextField, ToggleButton, ToggleButtonGroup, Tooltip, Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import {
    severityChoices, statusLabel, presenceChoices, kindChoices, tierChoices, tierLabel, reviewActionLabels,
    reviewActionToasts, ALLOWED_ACTIONS, STATUS_COLORS, openStatuses, openQueueFilter, QUEUES, queueFilter,
} from './choices';
import {
    Ago, AsOf, BulkResultTable, Clipped, DetailsSection, FilterChips, Loaded, OpenHint, PresenceChip, RulePicker,
    ScalePagination, SimpleTable, StaleChip, StatusChip, TagChips, TruncatedNote, fmtDate, fmtEstimate, fmtNum, fmtPct,
    listUrl, pluralize, showUrl, useCategories, useFetch, useObjectTypeChoices,
} from './common';
import { scopedTitle, useScope } from './scope';

// Review at scale: tabs counted by one GET /hits/aggregate (the same queue definition as the badge and the Work desk,
// choices.js QUEUES); the cluster board (GET /hits/clusters) as the default view with "Decide cluster" (POST
// /hits/decide: dry run, expected_total, undo); the flat list with keyboard triage as a mode and inside a cluster.
// Labels and chips come from choices.js / common.js (one vocabulary); allowed actions come from the server
// (`allowed_actions` per row) with ALLOWED_ACTIONS as the client fallback.

const BULK_MAX = 50;
const subjectOf = r => `${r.object_name || r.object_key || ''}${r.field_name ? `.${r.field_name}` : ''}`;
const allowedOf = r => (r && (r.allowed_actions ?? ALLOWED_ACTIONS[r.status])) || [];
const projectLink = r => (r && r.project_id ? showUrl('projects', r.project_id) : listUrl('projects', { q: r && r.project_path }));

// ---- tabs ------------------------------------------------------------------------------------------------------

const TABS = {
    questions: { ...QUEUES.questions, filter: queueFilter('questions'), queue: true },
    todecide: { label: 'To decide', filter: { status: openStatuses, asked_by_model: false, field_marks: false }, queue: true,
        hint: 'Pending review and model unsure together: the clusters to decide (questions are answered one by one)' },
    pending: { ...QUEUES.pending, filter: queueFilter('pending'), queue: true },
    unsure: { ...QUEUES.unsure, filter: queueFilter('unsure'), queue: true },
    harness: { label: 'Verified by harness', filter: { decided_tier: 'harness', status: ['match', 'no_match'], presence: 'all' },
        hint: 'Decisions of the harness model (audit)' },
    all: { label: 'All', filter: { presence: 'all' }, hint: 'Every hit, including removed code' },
};
const QUEUE_TABS = ['questions', 'todecide', 'pending', 'unsure'];
const TAB_KEYS = ['status', 'asked_by_model', 'decided_tier', 'presence', 'field_marks'];
// filter keys the UI keeps for itself (the data provider never sends them)
const UI_KEYS = ['view'];
const tabFilter = id => ({ ...TABS[id].filter });

const tabOf = f => {
    if (f.asked_by_model === true || f.asked_by_model === 'true') return 'questions';
    if (f.decided_tier === 'harness') return 'harness';
    const s = Array.isArray(f.status) ? f.status : (f.status ? [f.status] : []);
    if (s.includes('pending_review') && s.includes('need_more_info')) return 'todecide';
    if (f.status === 'pending_review') return 'pending';
    if (f.status === 'need_more_info') return 'unsure';
    return 'all';
};

// the filters of the view besides the tab and the UI keys (rule, project, category, ..., cluster)
const extraFilters = f => Object.fromEntries(Object.entries(f || {}).filter(([k]) => !TAB_KEYS.includes(k) && !UI_KEYS.includes(k)));
// what the data provider sends for the current view (the tab's filter included)
const apiFilterOf = f => Object.fromEntries(Object.entries(f || {}).filter(([k]) => !UI_KEYS.includes(k)));

// One GET /hits/aggregate (by queue x presence x field mark, presence all) under the view's extra filters: every tab
// count comes out of it. The queue tabs count live hits without field marks (as the queues do), "Verified by
// harness" and "All" count everything. Served from the statistics snapshot unless a filter needs a live query.
const useTabCounts = (filterValues, scope) => {
    const dataProvider = useDataProvider();
    const extra = extraFilters(filterValues);
    const key = JSON.stringify(extra);
    return useFetch(() => dataProvider.hitsAggregate({ by: ['queue', 'presence', 'field_mark'], filter: { ...extra, presence: 'all' } })
        .then(({ data }) => {
            const rows = data.rows || [];
            const live = r => r.presence !== 'gone' && !r.field_mark;
            const sum = pred => rows.filter(pred).reduce((n, r) => n + (Number(r.n) || 0), 0);
            const counts = {
                questions: sum(r => r.queue === 'questions' && live(r)),
                pending: sum(r => r.queue === 'pending' && live(r)),
                unsure: sum(r => r.queue === 'unsure' && live(r)),
                harness: sum(r => r.queue === 'harness'),
                all: sum(() => true),
            };
            counts.todecide = counts.pending + counts.unsure;
            return { data: { counts, computed_at: data.computed_at, snapshot: data.snapshot } };
        }), [key, scope]);
};

const firstNonEmpty = counts => QUEUE_TABS.find(id => counts && counts[id]) || 'all';

// counts reload after a decision (debounced), and the last decision by filter for the Undo toast
const ReviewContext = createContext({ bump: () => {}, announce: () => {} });
const useReview = () => useContext(ReviewContext);

const FILTER_LABELS = {
    status: v => `Status: ${(Array.isArray(v) ? v : [v]).map(statusLabel).join(' / ')}`,
    asked_by_model: v => (v === true || v === 'true' ? 'Asked by the harness model' : 'Not asked by the harness model'),
    decided_tier: v => `Decided by: ${tierLabel(v)}`,
    presence: v => `Presence: ${(presenceChoices.find(c => c.id === v) || { name: v }).name}`,
    field_marks: v => (v === true || v === 'true' ? 'Field marks only' : 'Field marks hidden'),
    cluster: v => `Cluster: ${String(v).length > 48 ? `${String(v).slice(0, 47)}…` : v}`,
};

const viewOf = f => (tabOf(f) === 'questions' || tabOf(f) === 'harness' ? 'list' : (f.view || 'clusters'));

const QueueTabs = ({ counts }) => {
    const { filterValues, setFilters, displayedFilters } = useListContext();
    const switched = useRef(false);
    const kept = () => Object.fromEntries(Object.entries(filterValues).filter(([k]) => !TAB_KEYS.includes(k)));
    const select = (e, value) => setFilters({ ...kept(), ...tabFilter(value) }, displayedFilters);
    // once, after the counts: a remembered or linked queue tab that is empty while another queue is not switches to
    // that queue (never open on nothing)
    useEffect(() => {
        if (switched.current || !counts.data) return;
        switched.current = true;
        const current = tabOf(filterValues);
        if (!QUEUE_TABS.includes(current)) return;
        const tabOnly = !Object.keys(extraFilters(filterValues)).length;
        if (tabOnly && !counts.data.counts[current]) {
            const wanted = firstNonEmpty(counts.data.counts);
            if (wanted !== current) select(null, wanted);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [counts.data]);
    const remove = key => {
        const next = { ...filterValues };
        delete next[key];
        setFilters(next, displayedFilters);
    };
    const chips = [...TAB_KEYS, 'cluster'].filter(k => filterValues[k] !== undefined && filterValues[k] !== null)
        .map(k => ({ key: k, label: FILTER_LABELS[k](filterValues[k]) }));
    const n = (counts.data && counts.data.counts) || {};
    const label = id => (n[id] === undefined || n[id] === null ? TABS[id].label : `${TABS[id].label} (${fmtNum(n[id])})`);
    const view = viewOf(filterValues);
    const setView = (e, v) => v && setFilters({ ...filterValues, view: v }, displayedFilters);
    const fixedList = view === 'list' && !filterValues.view;
    return (
        <Box>
            <Box display="flex" alignItems="center" flexWrap="wrap" gap={1}>
                <Tabs value={tabOf(filterValues)} onChange={select} sx={{ px: 1, flex: 1, minWidth: 0 }} variant="scrollable" scrollButtons="auto">
                    {Object.keys(TABS).map(id => (
                        <Tab key={id} value={id} label={<Tooltip title={TABS[id].hint}><span>{label(id)}</span></Tooltip>} />
                    ))}
                </Tabs>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ pr: 1 }}>
                    {counts.data && <AsOf value={counts.data.computed_at} snapshot={counts.data.snapshot} prefix="counts" />}
                    <Tooltip title={fixedList ? 'Questions and harness decisions are read one by one' : 'Clusters: the open hits grouped by schema, field, name or rule x group, decided together. List: one hit at a time with the keyboard.'}>
                        <ToggleButtonGroup size="small" exclusive value={view} onChange={setView} aria-label="View" disabled={fixedList}>
                            <ToggleButton value="clusters">Clusters</ToggleButton>
                            <ToggleButton value="list">List</ToggleButton>
                        </ToggleButtonGroup>
                    </Tooltip>
                </Stack>
            </Box>
            {chips.length > 0 && (
                <Box px={1} py={0.5}>
                    <FilterChips items={chips} onRemove={remove} />
                </Box>
            )}
        </Box>
    );
};

// ---- filters ---------------------------------------------------------------------------------------------------

// the rules of both kinds by name, searched on the server (GET /rules?q=)
const RuleFilter = ({ source, label }) => {
    const { filterValues, setFilters, displayedFilters } = useListContext();
    const value = filterValues[source];
    return (
        <RulePicker value={value === undefined ? null : value} label={label} sx={{ minWidth: 220 }}
                    onChange={id => {
                        const next = { ...filterValues };
                        if (id === null) delete next[source]; else next[source] = id;
                        setFilters(next, displayedFilters);
                    }} />
    );
};

// categories of the rules and hits (GET /categories), free text allowed
const CategoryFilter = props => {
    const names = useCategories();
    const [extra, setExtra] = useState([]);
    const choices = useMemo(() => [...new Set([...names, ...extra])].sort().map(c => ({ id: c, name: c })), [names, extra]);
    return (
        <AutocompleteInput {...props} choices={choices}
                           onCreate={value => { if (!value) return null; setExtra(x => [...x, value]); return { id: value, name: value }; }} />
    );
};

// object types with counts (GET /object_types)
const ObjectTypeFilter = props => <SelectInput {...props} choices={useObjectTypeChoices()} />;

const filters = [
    <ReferenceInput source="project_id" reference="projects" alwaysOn>
        <AutocompleteInput optionText="full_path" filterToQuery={q => ({ q })} label="Project" />
    </ReferenceInput>,
    <TextInput source="q" label="Object / field" alwaysOn />,
    <RuleFilter source="rule_id" label="Rule" alwaysOn />,
    <CategoryFilter source="category" label="Category" />,
    <SelectInput source="severity" choices={severityChoices} />,
    <SelectInput source="kind" label="Rule kind" choices={kindChoices} />,
    <ObjectTypeFilter source="object_type" label="Object type" />,
    <SelectInput source="decided_tier" label="Decided by" choices={tierChoices} />,
    <SelectInput source="stale" label="Stale (older rule version)" choices={[{ id: true, name: 'Stale' }, { id: false, name: 'Current' }]} />,
    <DateInput source="reviewed_after" label="Reviewed after" />,
    <DateInput source="first_seen_after" label="First seen after" />,
    <SelectInput source="presence" choices={presenceChoices} emptyText="Main or open MRs" />,
    <SelectInput source="field_marks" label="Field marks" choices={[{ id: false, name: 'Hide' }, { id: true, name: 'Only' }]} />,
];

// ---- review dialogs --------------------------------------------------------------------------------------------

const SeveritySelect = ({ value, onChange, keepText = "(keep the rule's)" }) => (
    <MuiTextField select label="Severity" value={value} onChange={e => onChange(e.target.value)} fullWidth margin="dense">
        <MenuItem value="">{keepText}</MenuItem>
        {severityChoices.map(c => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
    </MuiTextField>
);

const LAST_NOTE_KEY = 'review_last_note';
const readLastNote = () => { try { return localStorage.getItem(LAST_NOTE_KEY) || ''; } catch (e) { return ''; } };
const saveLastNote = note => { if (note) { try { localStorage.setItem(LAST_NOTE_KEY, note); } catch (e) { /* ignore */ } } };
const AUTO_ADVANCE_KEY = 'review_auto_advance';
const readAutoAdvance = () => { try { return localStorage.getItem(AUTO_ADVANCE_KEY) !== 'off'; } catch (e) { return true; } };
const CLUSTER_BY_KEY = 'review_cluster_by';
const readClusterBy = () => { try { return localStorage.getItem(CLUSTER_BY_KEY) || 'schema'; } catch (e) { return 'schema'; } };

const cascadeText = n => (n ? ` (+${n} field ${n === 1 ? 'mark' : 'marks'})` : '');

// One decision (POST /hits/{id}/review). Ctrl/Cmd+Enter applies; the last note is remembered for the next one.
const ReviewDialog = ({ action, record, onClose, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    const { bump } = useReview();
    const [category, setCategory] = useState(record.category || '');
    const [severity, setSeverity] = useState(record.severity || '');
    const [note, setNote] = useState('');
    const [busy, setBusy] = useState(false);
    const lastNote = readLastNote();

    const submit = () => {
        if (busy || (action === 'request_info' && !note)) return;
        setBusy(true);
        const data = { action, note: note || null };
        if (action === 'confirm') {
            data.category = category || null;
            data.severity = severity || null;
        }
        dataProvider.review('hits', { id: record.id, data })
            .then(({ data: r }) => {
                saveLastNote(note);
                notify(`${reviewActionToasts[action]}${cascadeText(r && r.cascaded)}`, { type: 'info' });
                refresh();
                bump();
                onClose();
                if (onDone) onDone();
            })
            .catch(e => notify(e.message || 'Review failed', { type: 'warning' }))
            .finally(() => setBusy(false));
    };
    const onKeyDown = e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); submit(); } };

    return (
        <Dialog open onClose={onClose} fullWidth aria-labelledby="review-title" onKeyDown={onKeyDown}>
            <DialogTitle id="review-title">{reviewActionLabels[action]}: {subjectOf(record)}</DialogTitle>
            <DialogContent>
                {record.asked_by_model && record.note && (
                    <Alert severity="info" sx={{ mb: 1, whiteSpace: 'pre-wrap' }}>
                        <b>Question from the harness model: </b>{record.note}
                    </Alert>
                )}
                {action === 'confirm' && (
                    <>
                        <MuiTextField label="Category" value={category} onChange={e => setCategory(e.target.value)}
                                      fullWidth margin="dense" autoFocus />
                        <SeveritySelect value={severity} onChange={setSeverity} />
                    </>
                )}
                <MuiTextField label={action === 'request_info' ? 'What is missing? (required)' : 'Note'} value={note}
                              onChange={e => setNote(e.target.value)} fullWidth multiline minRows={3} margin="dense"
                              autoFocus={action !== 'confirm'} />
                {lastNote && !note && (
                    <Button label={`Use the last note: "${lastNote.slice(0, 60)}${lastNote.length > 60 ? '…' : ''}"`} size="small"
                            onClick={() => setNote(lastNote)} />
                )}
                <Typography variant="caption" color="text.secondary" component="div">Ctrl/Cmd + Enter applies</Typography>
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                <Button label={reviewActionLabels[action]} variant="contained" onClick={submit}
                        disabled={busy || (action === 'request_info' && !note)} />
            </DialogActions>
        </Dialog>
    );
};

// POST /hits/review_bulk: the dry run runs by itself (on open and when the note changes), one Apply button.
const BulkReviewDialog = ({ action, ids, onClose }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    const { bump } = useReview();
    const unselectAll = useUnselectAll('hits');
    const [note, setNote] = useState(readLastNote);
    const [category, setCategory] = useState('');
    const [severity, setSeverity] = useState('');
    const [preview, setPreview] = useState(null);
    const [busy, setBusy] = useState(false);

    const payload = dryRun => {
        const data = { hit_ids: ids, action, note, dry_run: dryRun };
        if (action === 'confirm') {
            data.category = category || null;
            data.severity = severity || null;
        }
        return data;
    };
    useEffect(() => {
        if (!note.trim()) { setPreview(null); return undefined; }
        let alive = true;
        const timer = setTimeout(() => {
            dataProvider.reviewBulk({ data: payload(true) })
                .then(({ data: r }) => alive && setPreview(r))
                .catch(e => alive && setPreview({ error: e.message || 'Dry run failed' }));
        }, 400);
        return () => { alive = false; clearTimeout(timer); };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [note, category, severity, ids.join(',')]);

    const apply = () => {
        setBusy(true);
        dataProvider.reviewBulk({ data: payload(false) })
            .then(({ data: r }) => {
                saveLastNote(note);
                notify(`${reviewActionToasts[action]}: ${r.changed} of ${ids.length}`, { type: 'info' });
                unselectAll();
                refresh();
                bump();
                onClose();
            })
            .catch(e => notify(e.message || 'Bulk review failed', { type: 'warning' }))
            .finally(() => setBusy(false));
    };
    const ok = preview && preview.items ? preview.items.filter(i => i.result === 'ok').length : 0;

    return (
        <Dialog open onClose={onClose} fullWidth maxWidth="md" aria-labelledby="bulk-review-title">
            <DialogTitle id="bulk-review-title">{reviewActionLabels[action]}: {ids.length} hits</DialogTitle>
            <DialogContent>
                <Typography variant="body2" gutterBottom>
                    One note for all of them (why they get the same decision). Hits whose status does not allow the action
                    are skipped.
                </Typography>
                {action === 'confirm' && (
                    <>
                        <MuiTextField label="Category (empty: keep each hit's)" value={category} fullWidth margin="dense"
                                      onChange={e => setCategory(e.target.value)} />
                        <SeveritySelect value={severity} onChange={setSeverity} />
                    </>
                )}
                <MuiTextField label="Note (required)" value={note} onChange={e => setNote(e.target.value)}
                              fullWidth multiline minRows={2} margin="dense" autoFocus />
                <Box mt={2}>
                    {!note.trim() && <Typography variant="body2" color="text.secondary">Write a note to see what would change.</Typography>}
                    {note.trim() && !preview && <Skeleton variant="rectangular" height={48} />}
                    {preview && preview.error && <Alert severity="warning">{preview.error}</Alert>}
                    {preview && preview.items && (
                        <>
                            <Typography variant="subtitle2">{ok} of {preview.items.length} will change</Typography>
                            <BulkResultTable items={preview.items} idOf={i => i.id} />
                        </>
                    )}
                </Box>
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                <Button label={`Apply to ${ok}`} variant="contained" onClick={apply} disabled={busy || !preview || !ok || !note.trim()} />
            </DialogActions>
        </Dialog>
    );
};

const BulkReviewButtons = () => {
    const { selectedIds, data = [], onSelect } = useListContext();
    const [action, setAction] = useState(null);
    const tooMany = selectedIds.length > BULK_MAX;
    return (
        <>
            <Button label="Select all on page" onClick={() => onSelect(data.map(r => r.id))} />
            {Object.keys(reviewActionLabels).map(a => (
                <Button key={a} label={reviewActionLabels[a]} disabled={tooMany} onClick={() => setAction(a)} />
            ))}
            {tooMany && <Typography variant="caption" color="error">At most {BULK_MAX} hits per bulk decision</Typography>}
            {action && <BulkReviewDialog action={action} ids={selectedIds} onClose={() => setAction(null)} />}
        </>
    );
};

// ---- decide by filter (a cluster, or everything the current filter matches) -----------------------------------------

const DECIDE_ACTIONS = ['confirm', 'reject', 'request_info'];
const narrows = f => Object.keys(f || {}).some(k => k !== 'presence' && !UI_KEYS.includes(k));

// POST /hits/decide. The dry run runs by itself once there is a note (why these hits get the same decision) and
// again when the note / category / severity change; Apply sends the dry run's `matched` as expected_total and the
// server refuses (409) when the set changed meanwhile - then the dry run runs again. The result is a batch with
// Undo (the toast of the page and the "Recent decisions by filter" section).
const DecideDialog = ({ action, filter, title, onClose, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    const { bump, announce } = useReview();
    const [note, setNote] = useState(readLastNote);
    const [category, setCategory] = useState('');
    const [severity, setSeverity] = useState('');
    const [includeHuman, setIncludeHuman] = useState(false);
    const [preview, setPreview] = useState(null);
    const [busy, setBusy] = useState(false);
    const [tick, setTick] = useState(0);

    const payload = dryRun => {
        const data = { filter, action, note, dry_run: dryRun, include_human: includeHuman, skip_questions: true };
        if (action === 'confirm') {
            data.category = category || null;
            data.severity = severity || null;
        }
        if (!dryRun) data.expected_total = preview.matched;
        return data;
    };
    useEffect(() => {
        if (!note.trim()) { setPreview(null); return undefined; }
        let alive = true;
        const timer = setTimeout(() => {
            dataProvider.decideHits({ data: payload(true) })
                .then(({ data: r }) => alive && setPreview(r))
                .catch(e => alive && setPreview({ error: e.message || 'Dry run failed' }));
        }, 400);
        return () => { alive = false; clearTimeout(timer); };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [note, category, severity, includeHuman, tick, JSON.stringify(filter)]);

    const apply = () => {
        setBusy(true);
        dataProvider.decideHits({ data: payload(false) })
            .then(({ data: r }) => {
                saveLastNote(note);
                announce(r);
                notify(`${reviewActionToasts[action]}: ${fmtNum(r.applied)} hits${cascadeText(r.cascaded)} · batch #${r.batch_id}`, { type: 'info' });
                refresh();
                bump();
                onClose();
                if (onDone) onDone(r);
            })
            .catch(e => {
                if (e.status === 409) { notify('The set changed since the dry run: it runs again', { type: 'warning' }); setPreview(null); setTick(t => t + 1); }
                else notify(e.message || 'Decision failed', { type: 'warning' });
            })
            .finally(() => setBusy(false));
    };
    const p = preview && !preview.error ? preview : null;
    const kept = p ? p.kept || {} : {};
    const keptText = p ? [
        kept.human && `${fmtNum(kept.human)} decided by a human (kept)`,
        kept.harness && `${fmtNum(kept.harness)} decided by the harness model (kept)`,
        kept.questions && `${fmtNum(kept.questions)} questions of the model (answer them one by one)`,
        kept.transition && `${fmtNum(kept.transition)} whose status does not allow "${reviewActionLabels[action].toLowerCase()}"`,
    ].filter(Boolean) : [];

    return (
        <Dialog open onClose={onClose} fullWidth maxWidth="md" aria-labelledby="decide-title">
            <DialogTitle id="decide-title">{reviewActionLabels[action]}: {title}</DialogTitle>
            <DialogContent>
                <Typography variant="body2" gutterBottom>
                    One decision on every hit the filter matches, with one note (why they get the same decision). The dry
                    run below says what changes and what is kept; Apply refuses when the set changed meanwhile. Every
                    batch can be undone.
                </Typography>
                {action === 'confirm' && (
                    <>
                        <MuiTextField label="Category (empty: keep each hit's)" value={category} fullWidth margin="dense"
                                      onChange={e => setCategory(e.target.value)} />
                        <SeveritySelect value={severity} onChange={setSeverity} keepText="(keep each hit's)" />
                    </>
                )}
                <MuiTextField label="Note (required)" value={note} onChange={e => setNote(e.target.value)}
                              fullWidth multiline minRows={2} margin="dense" autoFocus />
                <FormControlLabel label={<Typography variant="caption">also re-decide hits a human decided before</Typography>}
                                  control={<Checkbox size="small" checked={includeHuman} onChange={e => setIncludeHuman(e.target.checked)} />} />
                <Box mt={1}>
                    {!note.trim() && <Typography variant="body2" color="text.secondary">Write a note to see the dry run.</Typography>}
                    {note.trim() && !preview && <Skeleton variant="rectangular" height={64} />}
                    {preview && preview.error && <Alert severity="warning">{preview.error}</Alert>}
                    {p && (
                        <Stack spacing={1}>
                            <Typography variant="subtitle2">
                                {fmtNum(p.matched)} hits will become {statusLabel(p.target_status)}
                                {p.by_status && Object.keys(p.by_status).length > 0 && (
                                    <Typography component="span" variant="body2" color="text.secondary">
                                        {' '}(now {Object.entries(p.by_status).map(([s, n]) => `${fmtNum(n)} ${statusLabel(s).toLowerCase()}`).join(', ')})
                                    </Typography>
                                )}
                            </Typography>
                            {keptText.length > 0 && <Typography variant="body2" color="text.secondary">Kept: {keptText.join('; ')}</Typography>}
                            {p.by_project && p.by_project.length > 0 && (
                                <Box>
                                    <Typography variant="caption" color="text.secondary">
                                        By project{p.by_project_more ? ` (top ${p.by_project.length} of ${fmtNum(p.by_project.length + p.by_project_more)})` : ''}:
                                    </Typography>
                                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                                        {p.by_project.map(x => (
                                            <Chip key={x.project_id} size="small" variant="outlined" component={Link} clickable
                                                  to={showUrl('projects', x.project_id)} label={`${x.project_path} · ${fmtNum(x.n)}`} />
                                        ))}
                                        {p.by_project_more > 0 && <Chip size="small" variant="outlined" label={`${fmtNum(p.by_project_more)} more projects`} />}
                                    </Stack>
                                </Box>
                            )}
                            {p.sample && p.sample.length > 0 && (
                                <Typography variant="caption" color="text.secondary">
                                    Sample: {p.sample.map((id, i) => <span key={id}>{i ? ' · ' : ''}<Link to={showUrl('hits', id)}>{id}</Link></span>)}
                                </Typography>
                            )}
                        </Stack>
                    )}
                </Box>
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                <Button label={p ? `Apply to ${fmtNum(p.matched)}` : 'Apply'} variant="contained" onClick={apply}
                        disabled={busy || !p || !p.matched || !note.trim()} />
            </DialogActions>
        </Dialog>
    );
};

// the three decisions on the whole filtered set (list mode toolbar); needs a filter that narrows the hits
const DecideByFilterButtons = () => {
    const { filterValues, total } = useListContext();
    const [action, setAction] = useState(null);
    const filter = apiFilterOf(filterValues);
    const can = narrows(filter);
    return (
        <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap>
            <Tooltip title={can ? 'The same decision on every hit the current filters match (dry run first, undo after)' : 'Narrow the hits first (a tab, a rule, a cluster, a project)'}>
                <Typography variant="caption" color="text.secondary">Decide all{total ? ` ${fmtNum(total)}` : ''}:</Typography>
            </Tooltip>
            {DECIDE_ACTIONS.map(a => <Button key={a} size="small" label={reviewActionLabels[a]} disabled={!can} onClick={() => setAction(a)} />)}
            {action && <DecideDialog action={action} filter={filter} title={`every hit of the current filter${filterValues.cluster ? ' (cluster)' : ''}`}
                                     onClose={() => setAction(null)} />}
        </Stack>
    );
};

// "Batch #412 applied to 1 237 hits · Undo" for a minute after a decision by filter
const UndoSnackbar = ({ batch, onClose }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    const { bump } = useReview();
    const [busy, setBusy] = useState(false);
    if (!batch) return null;
    const undo = () => {
        setBusy(true);
        dataProvider.undoDecision({ id: batch.batch_id })
            .then(({ data: r }) => { notify(`Batch #${r.batch_id} undone: ${fmtNum(r.restored)} restored${r.skipped ? `, ${fmtNum(r.skipped)} decided again since (kept)` : ''}`, { type: 'info' }); refresh(); bump(); onClose(); })
            .catch(e => notify(e.message || 'Undo failed', { type: 'warning' }))
            .finally(() => setBusy(false));
    };
    return (
        <Snackbar open autoHideDuration={60000} onClose={(e, reason) => reason !== 'clickaway' && onClose()}
                  anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
                  message={`Batch #${batch.batch_id}: ${reviewActionToasts[batch.action] || batch.action} on ${fmtNum(batch.applied)} hits${cascadeText(batch.cascaded)}`}
                  action={(
                      <>
                          <Button label="Undo" color="inherit" size="small" onClick={undo} disabled={busy} />
                          <IconButton size="small" color="inherit" onClick={onClose} aria-label="Close"><CloseIcon fontSize="small" /></IconButton>
                      </>
                  )} />
    );
};

// GET /review_batches: the decisions by filter (newest first) with Undo
const RecentBatches = () => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    const { bump } = useReview();
    const state = useFetch(() => dataProvider.reviewBatches({ limit: 20 }), []);
    const undo = b => dataProvider.undoDecision({ id: b.id })
        .then(({ data: r }) => { notify(`Batch #${r.batch_id} undone: ${fmtNum(r.restored)} restored${r.skipped ? `, ${fmtNum(r.skipped)} kept` : ''}`, { type: 'info' }); state.reload(); refresh(); bump(); })
        .catch(e => notify(e.message || 'Undo failed', { type: 'warning' }));
    const filterText = f => Object.entries(f || {}).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('|') : v}`).join(' ');
    return (
        <Loaded state={state}>
            {d => (
                <SimpleTable rows={d.items} rowKey={b => b.id} empty="No decision by filter yet" columns={[
                    { label: 'Batch', render: b => `#${b.id}` },
                    { label: 'When', render: b => <Ago value={b.applied_at} /> },
                    { label: 'Who', render: b => `${b.reviewer}${b.via && b.via !== 'rest' ? ` (${b.via})` : ''}` },
                    { label: 'Decision', render: b => <StatusChip status={b.target_status} /> },
                    { label: 'Hits', render: b => `${fmtNum(b.applied)}${b.cascaded ? ` +${fmtNum(b.cascaded)} marks` : ''}` },
                    { label: 'Filter', render: b => <Clipped text={filterText(b.filter)} max={80} /> },
                    { label: 'Note', render: b => <Clipped text={b.note || ''} max={80} /> },
                    { label: '', render: b => (b.undone_at
                        ? <Typography variant="caption" color="text.secondary">undone <Ago value={b.undone_at} />{b.restored !== null && b.restored !== undefined ? ` (${fmtNum(b.restored)} restored)` : ''}</Typography>
                        : <Button size="small" label="Undo" onClick={() => undo(b)} />) },
                ]} />
            )}
        </Loaded>
    );
};

// ---- evidence --------------------------------------------------------------------------------------------------

const QuestionAlert = ({ hit }) => (
    <Alert severity="info" sx={{ whiteSpace: 'pre-wrap' }}>
        <Typography variant="subtitle2">Question from the harness model</Typography>
        <Typography variant="body2" sx={{ mt: 0.5 }}>{hit.note}</Typography>
        <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
            If you do not know: <Link to={projectLink(hit)}>Open the project</Link>
            {' '}and ask its owners. Mark as match / no match answers it; Reopen puts the hit back to Pending review.
        </Typography>
    </Alert>
);

// who said what: the service model, the harness model (if it looked), the human (if one decided)
const verdictRows = hit => {
    const tier = hit.decided_tier;
    const serviceStatus = tier === 'service' || !tier ? hit.status : hit.machine_status;
    const serviceReason = hit.service_reason ?? (tier === 'service' || !tier ? hit.reason : null);
    const rows = [{
        k: 'service', who: 'Service model', detail: hit.model, status: serviceStatus, text: serviceReason,
        at: tier === 'service' ? hit.reviewed_at : null,
    }];
    if (hit.verifier_model || tier === 'harness' || hit.asked_by_model) {
        rows.push({
            k: 'harness', who: 'Harness model', detail: hit.verifier_model,
            status: tier === 'harness' ? hit.status : (hit.asked_by_model ? 'need_more_info' : null),
            text: tier === 'harness' ? hit.reason : (hit.asked_by_model ? 'asked a human (question above)' : null),
            at: hit.verified_at,
        });
    }
    rows.push({
        k: 'human', who: 'Human', detail: tier === 'human' ? hit.reviewer : null,
        status: tier === 'human' ? hit.status : null, text: tier === 'human' && !hit.asked_by_model ? hit.note : null,
        at: tier === 'human' ? hit.reviewed_at : null,
    });
    return rows;
};

// the open MRs a hit's object is in (GET /hits/{id} presence rows), as "MR !412" chips
const MrChips = ({ hit }) => {
    const mrs = (hit.presence || []).filter(p => p.mr_iid);
    if (!mrs.length) return null;
    return mrs.slice(0, 5).map(p => (
        <Tooltip key={p.branch_id} title={`${p.mr_title || ''} (${p.branch_name}${p.change ? `, ${p.change}` : ''})`}>
            <Chip size="small" variant="outlined" label={`MR !${p.mr_iid}`} />
        </Tooltip>
    ));
};

const Verdict = ({ hit }) => (
    <Paper variant="outlined" sx={{ p: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 0.5 }}>
            <Typography variant="subtitle2">Verdicts</Typography>
            <PresenceChip hit={hit} />
            {!hit.in_main && <MrChips hit={hit} />}
        </Stack>
        <Table size="small">
            <TableBody>
                {verdictRows(hit).map(r => (
                    <TableRow key={r.k}>
                        <TableCell sx={{ whiteSpace: 'nowrap', fontWeight: hit.decided_tier === r.k ? 'bold' : 'normal' }}>
                            {r.who}
                            {r.detail && <Typography variant="caption" color="text.secondary" component="div">{r.detail}</Typography>}
                        </TableCell>
                        <TableCell sx={{ whiteSpace: 'nowrap' }}>{r.status ? <StatusChip status={r.status} /> : '—'}</TableCell>
                        <TableCell sx={{ whiteSpace: 'pre-wrap' }}>
                            {r.text || ''}
                            {r.at && <Typography variant="caption" color="text.secondary" component="div">{fmtDate(r.at)}</Typography>}
                        </TableCell>
                    </TableRow>
                ))}
            </TableBody>
        </Table>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
            <Typography variant="body2">
                {hit.category || '-'}{hit.severity ? ` / ${hit.severity}` : ''}
                {hit.rule ? ` · rule ${hit.rule.name} (${hit.rule.target || hit.rule.kind}, ${hit.rule.mode}, v${hit.rule.version}; hit v${hit.rule_version})` : ` · rule ${hit.rule_name}`}
            </Typography>
            <StaleChip hit={hit} />
            {hit.tags && hit.tags.length > 0 && <TagChips tags={hit.tags} />}
        </Stack>
        {!hit.field_name && hit.fields && hit.fields.length > 0 && (
            <Typography variant="body2" sx={{ mt: 0.5 }}>Fields named by the model: {hit.fields.join(', ')}</Typography>
        )}
    </Paper>
);

const actorOf = i => (i.decided_tier === 'human' ? (i.reviewer || 'Human')
    : (i.decided_tier === 'harness' ? (i.verifier_model || 'Harness model') : (i.model || 'Service model')));

// the last three verdicts of the hit (GET /hits/{id}/history); the full table is on the hit page
const MiniHistory = ({ hitId, compact }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.hitHistory({ id: hitId }).catch(() => ({ data: { items: [] } })), [hitId]);
    return (
        <Loaded state={state}>
            {h => {
                const items = (h.items || []).slice(0, 3);
                if (!items.length) return null;
                return (
                    <Box>
                        <Typography variant="subtitle2">
                            History ({items.length} of {(h.items || []).length}{h.truncated ? '+' : ''})
                            {compact && <> · <Link to={showUrl('hits', hitId)}>Open page</Link></>}
                        </Typography>
                        <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                            {items.map(i => (
                                <Stack key={i.id} direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                                    <Chip size="small" variant="outlined" label={`${tierLabel(i.decided_tier)}${actorOf(i) !== tierLabel(i.decided_tier) ? `: ${actorOf(i)}` : ''}`} />
                                    <StatusChip status={i.status} />
                                    {i.batch_id && <Chip size="small" variant="outlined" label={`batch #${i.batch_id}${i.source === 'undo' ? ' undo' : ''}`} />}
                                    <Typography variant="caption" color="text.secondary">v{i.rule_version} · <Ago value={i.created_at} /></Typography>
                                    <Typography variant="caption" component="span"><Clipped text={i.reason || ''} max={120} /></Typography>
                                </Stack>
                            ))}
                        </Stack>
                    </Box>
                );
            }}
        </Loaded>
    );
};

const HitChip = ({ hit }) => (
    <Chip component={Link} to={showUrl('hits', hit.id)} clickable size="small" color={STATUS_COLORS[hit.status] || 'default'}
          variant={hit.kind === 'manual' ? 'filled' : 'outlined'}
          label={`${hit.kind === 'manual' ? 'label' : hit.rule}: ${hit.category || '?'} ${hit.severity || ''} (${statusLabel(hit.status)})`} />
);

// the object with its fields: comments, samples and the other rules' hits come from GET /objects/{key}
const Fields = ({ hit, object }) => {
    const subject = new Set([hit.field_name, ...(hit.fields || [])].filter(Boolean));
    const rows = (object && object.fields) || (hit.object && hit.object.fields) || [];
    const lines = hit.object ? Object.fromEntries(hit.object.fields.map(f => [f.name, f.line])) : {};
    return (
        <Table size="small">
            <TableHead>
                <TableRow>
                    <TableCell>Field</TableCell><TableCell>Type</TableCell><TableCell>Comment / samples</TableCell><TableCell>Hits</TableCell>
                </TableRow>
            </TableHead>
            <TableBody>
                {rows.map(f => (
                    <TableRow key={f.name} selected={subject.has(f.name)}>
                        <TableCell>{subject.has(f.name) ? <b>{f.name}</b> : f.name}{lines[f.name] ? <Typography component="span" variant="caption" color="text.secondary"> :{lines[f.name]}</Typography> : null}</TableCell>
                        <TableCell>{f.type}</TableCell>
                        <TableCell>
                            {f.comment && <Typography variant="body2" color="text.secondary" component="div"><Clipped text={f.comment} max={160} /></Typography>}
                            {f.samples && f.samples.length > 0 && <Typography variant="caption">samples: {f.samples.join(', ')}</Typography>}
                        </TableCell>
                        <TableCell>
                            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap component="span">
                                {(f.hits || []).filter(h => h.id !== hit.id).map(h => <HitChip key={h.id} hit={h} />)}
                            </Stack>
                        </TableCell>
                    </TableRow>
                ))}
            </TableBody>
        </Table>
    );
};

// field marks of the same rule on this object (mark_fields): decided together with the object hit
const fieldMarksOf = detail => (!detail.field_name ? (detail.other_hits || []).filter(h => h.field_name
    && (h.rule_id !== undefined ? h.rule_id === detail.rule_id : h.rule_name === detail.rule_name)) : []);

// Everything a reviewer needs about one hit (GET /hits/{id} + GET /objects/{key}); the same panel in the triage
// view, the cluster sample and on the hit page.
export const Evidence = ({ detail, compact = false }) => {
    const dataProvider = useDataProvider();
    const object = useFetch(() => (detail.object
        ? dataProvider.getOne('objects', { id: detail.object_key }).catch(() => ({ data: null }))
        : Promise.resolve({ data: null })), [detail.object_key, !!detail.object]);   // the show page first renders the list's record (no object)
    const [showPrompt, setShowPrompt] = useState(false);
    const o = detail.object;
    const objectHits = object.data ? object.data.object_hits.filter(h => h.id !== detail.id) : null;
    const marks = fieldMarksOf(detail);
    return (
        <Stack spacing={1.5}>
            {detail.asked_by_model && detail.note && <QuestionAlert hit={detail} />}
            <Verdict hit={detail} />
            {detail.object !== undefined && <MiniHistory hitId={detail.id} compact={compact} />}
            {o ? (
                <Box>
                    <Typography variant="subtitle2">
                        {o.type} <Link to={showUrl('objects', o.object_key)}><b>{o.name}</b></Link>
                        <Typography component="span" variant="caption" color="text.secondary">
                            {' '}({o.parser}) · <Link to={projectLink(detail)}>{detail.project_path}</Link> · {o.file}{o.line ? `:${o.line}` : ''} · from {o.source}
                        </Typography>
                    </Typography>
                    {o.props && Object.keys(o.props).length > 0 && (
                        <Typography variant="caption" color="text.secondary" component="div">
                            {Object.entries(o.props).map(([k, v]) => `${k}=${v}`).join(', ')}
                        </Typography>
                    )}
                    {object.data && object.data.comment && (
                        <Typography variant="body2" color="text.secondary" component="div"><Clipped text={object.data.comment} max={240} /></Typography>
                    )}
                    {object.data && object.data.tags && object.data.tags.length > 0 && <TagChips tags={object.data.tags} />}
                    {objectHits && objectHits.length > 0 && (
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 0.5 }}>
                            {objectHits.map(h => <HitChip key={h.id} hit={h} />)}
                        </Stack>
                    )}
                </Box>
            ) : <Typography variant="body2">Object not available (no stored version)</Typography>}
            {o && (
                <Box sx={{ maxHeight: compact ? 360 : undefined, overflow: 'auto' }}>
                    <Loaded state={object}>{data => <Fields hit={detail} object={data} />}</Loaded>
                </Box>
            )}
            {marks.length > 0 && (
                <Typography variant="caption" color="text.secondary">
                    +{marks.length} field {marks.length === 1 ? 'mark' : 'marks'} of this rule ({marks.map(m => m.field_name).join(', ')}),
                    decided with the object.
                </Typography>
            )}
            <Box>
                <Typography variant="subtitle2">Present in</Typography>
                <SimpleTable rows={detail.presence} empty="Not present in any tracked branch" rowKey={p => p.branch_id} columns={[
                    { label: 'Branch', source: 'branch_name' },
                    { label: 'Main', source: 'is_main' },
                    { label: 'Change', source: 'change' },
                    { label: 'MR', render: p => (p.mr_iid ? `!${p.mr_iid} ${p.mr_title || ''}` : '') },
                ]} />
            </Box>
            {!object.data && detail.other_hits && detail.other_hits.length > 0 && (
                <Box>
                    <Typography variant="subtitle2">Other hits on this object</Typography>
                    <SimpleTable rows={detail.other_hits} rowKey={h => h.id} columns={[
                        { label: 'Rule', render: h => <Link to={showUrl('hits', h.id)}>{h.rule_name}</Link> },
                        { label: 'Field', source: 'field_name' },
                        { label: 'Status', render: h => <StatusChip status={h.status} /> },
                        { label: 'Category', source: 'category' },
                    ]} />
                </Box>
            )}
            {detail.rule && detail.rule.prompt && (
                <Box>
                    <Button label={showPrompt ? 'Hide the rule prompt' : 'Show the rule prompt'} size="small" onClick={() => setShowPrompt(!showPrompt)} />
                    <Collapse in={showPrompt}>
                        <Box component="pre" sx={{ whiteSpace: 'pre-wrap', fontSize: 12, m: 0, p: 1, bgcolor: 'action.hover' }}>{detail.rule.prompt}</Box>
                    </Collapse>
                </Box>
            )}
        </Stack>
    );
};

// ---- triage (list mode) -------------------------------------------------------------------------------------------

const KEY_ACTION = { c: 'confirm', r: 'reject', i: 'request_info', u: 'reopen' };
const KEYS = [['j / k', 'next / previous hit'], ['x', 'select / unselect (bulk decisions)'],
    ...Object.entries(KEY_ACTION).map(([k, a]) => [k, reviewActionLabels[a]]),
    ['o / Enter', 'open the hit page'], ['?', 'this help']];

const EvidencePanel = ({ hitId, onAction }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => (hitId ? dataProvider.getOne('hits', { id: hitId }) : Promise.resolve({ data: null })), [hitId]);
    if (!hitId) return <Typography variant="body2" color="text.secondary">Select a hit (click a row or press j).</Typography>;
    return (
        <Loaded state={state}>
            {detail => (detail ? (
                <Stack spacing={1}>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {allowedOf(detail).map(a => (
                            <Button key={a} label={`${reviewActionLabels[a]} (${Object.keys(KEY_ACTION).find(k => KEY_ACTION[k] === a)})`}
                                    variant={a === 'confirm' ? 'contained' : 'outlined'} size="small" onClick={() => onAction(a, detail)} />
                        ))}
                        <Button label="Open page (o)" size="small" component={Link} to={showUrl('hits', detail.id)} />
                    </Stack>
                    <Evidence detail={detail} compact />
                </Stack>
            ) : null)}
        </Loaded>
    );
};

// the subject of a row with its presence: In main / Only in open MR / Gone
const Subject = () => {
    const r = useRecordContext();
    if (!r) return null;
    const fields = !r.field_name && r.fields && r.fields.length ? ` (${r.fields.join(' + ')})` : '';
    return (
        <Box>
            <Typography variant="body2">{r.object_name || r.object_key}{r.field_name ? <b>.{r.field_name}</b> : ''}{fields}</Typography>
            <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography variant="caption" color="text.secondary">{r.project_path} · {r.object_type}</Typography>
                <PresenceChip hit={r} sx={{ height: 18, '& .MuiChip-label': { px: 0.75, fontSize: 11 } }} />
            </Stack>
        </Box>
    );
};

// open hits: why they wait (OpenHint); decided ones: who decided, and what the service model had said
const StatusCell = ({ r }) => {
    const open = ['pending_review', 'need_more_info'].includes(r.status);
    return (
        <Stack spacing={0.25}>
            <StatusChip status={r.status} />
            {open ? <OpenHint hit={r} /> : (
                <Typography variant="caption" color="text.secondary">
                    {tierLabel(r.decided_tier)}
                    {r.machine_status && r.decided_tier !== 'service' ? ` · service model said ${statusLabel(r.machine_status)}` : ''}
                </Typography>
            )}
            <StaleChip hit={r} />
        </Stack>
    );
};

const isTyping = e => ['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target && e.target.tagName) || '')
    || (e.target && e.target.isContentEditable);

// the persistent key hint: keys the focused hit does not allow are greyed out
const HintBar = ({ focused, selected, autoAdvance, setAutoAdvance, onHelp }) => {
    const allowed = focused ? allowedOf(focused) : Object.values(KEY_ACTION);
    const key = (k, label, enabled = true) => (
        <Typography key={k} component="span" variant="caption" color={enabled ? 'text.secondary' : 'text.disabled'}
                    sx={{ textDecoration: enabled ? 'none' : 'line-through' }}
                    title={enabled ? '' : `${label}: not allowed for this hit`}>
            {k} {label.toLowerCase()}
        </Typography>
    );
    return (
        <Box display="flex" alignItems="center" gap={1.5} mt={1} flexWrap="wrap">
            {selected ? <Typography variant="caption" color="text.secondary">{selected} selected ·</Typography> : null}
            {key('j/k', 'move')}
            {key('x', 'select')}
            {Object.entries(KEY_ACTION).map(([k, a]) => key(k, reviewActionLabels[a], allowed.includes(a)))}
            {key('o', 'page')}
            <Button label="? help" size="small" onClick={onHelp} />
            <FormControlLabel sx={{ ml: 'auto', mr: 0 }}
                              label={<Typography variant="caption">auto-advance</Typography>}
                              title="After a decision the cursor stays on its row, so the next hit of the queue is focused"
                              control={<Checkbox size="small" checked={autoAdvance} onChange={e => setAutoAdvance(e.target.checked)} />} />
        </Box>
    );
};

// List + evidence side by side; j/k move, x select, c/r/i/u decide the focused hit with the usual dialog.
const Triage = () => {
    const { data = [], selectedIds, onToggleItem, page, perPage, total, setPage } = useListContext();
    const redirect = useRedirect();
    const [cursor, setCursor] = useState(-1);
    const [dialog, setDialog] = useState(null);         // { action, record }
    const [help, setHelp] = useState(false);
    const [autoAdvance, setAuto] = useState(readAutoAdvance);
    const setAutoAdvance = v => { setAuto(v); try { localStorage.setItem(AUTO_ADVANCE_KEY, v ? 'on' : 'off'); } catch (e) { /* ignore */ } };
    const focused = cursor >= 0 && cursor < data.length ? data[cursor] : null;
    const focusedId = focused ? focused.id : null;

    const open = useCallback((action, record) => {
        if (!record || !allowedOf(record).includes(action)) return;
        setDialog({ action, record });
    }, []);

    useEffect(() => {
        const handler = e => {
            if (dialog || isTyping(e) || e.altKey || e.ctrlKey || e.metaKey) return;
            const last = data.length - 1;
            switch (e.key) {
                case 'j': case 'ArrowDown':
                    if (cursor < last) setCursor(cursor + 1);
                    else if (page * perPage < (total || 0)) { setPage(page + 1); setCursor(0); }
                    e.preventDefault(); break;
                case 'k': case 'ArrowUp':
                    if (cursor > 0) setCursor(cursor - 1);
                    else if (page > 1) { setPage(page - 1); setCursor(perPage - 1); }
                    e.preventDefault(); break;
                case 'x': if (focused) onToggleItem(focused.id); break;
                case 'o': case 'Enter': if (focused) redirect('show', 'hits', focused.id); break;
                case '?': setHelp(h => !h); break;
                default:
                    if (KEY_ACTION[e.key] && focused) open(KEY_ACTION[e.key], focused);
            }
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, [cursor, data, dialog, focused, onToggleItem, open, page, perPage, redirect, setPage, total]);

    useEffect(() => { if (cursor >= data.length) setCursor(data.length - 1); }, [data.length, cursor]);

    const rowSx = useCallback(record => (record.id === focusedId ? { bgcolor: 'action.selected' } : {}), [focusedId]);
    const rowClick = useCallback((id) => { setCursor(data.findIndex(r => r.id === id)); return false; }, [data]);
    // auto-advance: the cursor index stays, so the hit that takes the decided one's place is focused
    const decided = () => { if (!autoAdvance) setCursor(-1); };

    return (
        <Grid container spacing={1}>
            <Grid item xs={12} md={6} sx={{ minWidth: 0 }}>
                <Box px={1} py={0.5}><DecideByFilterButtons /></Box>
                <Box sx={{ overflowX: 'auto' }}>
                    <Datagrid rowClick={rowClick} rowSx={rowSx} bulkActionButtons={<BulkReviewButtons />} size="small"
                              empty={<Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>Nothing in this queue. Try another tab.</Typography>}>
                        <FunctionField label="Subject" sortBy="object_name" render={() => <Subject />} />
                        <FunctionField label="Rule" sortable={false} render={r => (
                            <Tooltip title={r.rule_name || ''}><Chip size="small" variant="outlined" label={r.rule_name} sx={{ maxWidth: 160 }} /></Tooltip>)} />
                        <FunctionField label="Status" sortBy="status" render={r => <StatusCell r={r} />} />
                        <FunctionField label="Age" sortBy="first_seen_at" render={r => <Ago value={r.first_seen_at} />} />
                    </Datagrid>
                </Box>
                <HintBar focused={focused} selected={selectedIds.length} autoAdvance={autoAdvance} setAutoAdvance={setAutoAdvance}
                         onHelp={() => setHelp(h => !h)} />
                <Collapse in={help}>
                    <Paper variant="outlined" sx={{ p: 1, mt: 1 }}>
                        <SimpleTable rows={KEYS.map(([k, v]) => ({ k, v }))} rowKey={r => r.k}
                                     columns={[{ label: 'Key', source: 'k' }, { label: 'Action', source: 'v' }]} />
                        <Typography variant="caption" color="text.secondary">
                            The service model never overwrites a human or harness decision, the harness model never a human one.
                            Bulk: select with x (at most {BULK_MAX}) and use the toolbar; "Decide all" decides every hit of the
                            current filter on the server (dry run, undo).
                        </Typography>
                    </Paper>
                </Collapse>
            </Grid>
            <Grid item xs={12} md={6} sx={{ minWidth: 0 }}>
                <Paper variant="outlined" sx={{ p: 1.5, position: 'sticky', top: 8, overflowX: 'auto' }}>
                    <EvidencePanel hitId={focusedId} onAction={open} />
                </Paper>
            </Grid>
            {dialog && (
                <ReviewDialog action={dialog.action} record={dialog.record} onClose={() => setDialog(null)} onDone={decided} />
            )}
        </Grid>
    );
};

// ---- cluster board (default view) ------------------------------------------------------------------------------------

const CLUSTER_BY = [
    ['schema', 'Same schema', 'object type + the same fields and types: one table copied into N services'],
    ['field_pattern', 'Same field', 'rule + field name: one field everywhere'],
    ['object_name', 'Same object name', 'rule + type + name: one table / RPC in N services'],
    ['rule_group', 'Rule × group × type', 'rule + GitLab group + object type'],
];
const CLUSTER_KEYS = [['j / k', 'next / previous sample'], ['c / r / i', 'decide the whole cluster'], ['l', 'open the cluster as a list'],
    ['o / Enter', 'open the focused sample'], ['Esc', 'back to the board'], ['?', 'this help']];

const clusterTitle = item => `${item.label || item.key} (${fmtNum(item.n_open)} open)`;

// the sample hits of a cluster (sample_ids, 5 point reads) with the evidence of the focused one
const ClusterPanel = ({ item, filter, onClose, onOpenList }) => {
    const dataProvider = useDataProvider();
    const redirect = useRedirect();
    const [cursor, setCursor] = useState(0);
    const [action, setAction] = useState(null);
    const [help, setHelp] = useState(false);
    const ids = item.sample_ids || [];
    const samples = useFetch(() => Promise.all(ids.map(id => dataProvider.getOne('hits', { id }).then(r => r.data).catch(() => null)))
        .then(rows => ({ data: rows.filter(Boolean) })), [ids.join(',')]);
    const rows = samples.data || [];
    const focused = rows[cursor] || null;
    const decideFilter = { ...filter, cluster: item.cluster };

    useEffect(() => {
        const handler = e => {
            if (action || isTyping(e) || e.altKey || e.ctrlKey || e.metaKey) return;
            switch (e.key) {
                case 'j': case 'ArrowDown': setCursor(c => Math.min(rows.length - 1, c + 1)); e.preventDefault(); break;
                case 'k': case 'ArrowUp': setCursor(c => Math.max(0, c - 1)); e.preventDefault(); break;
                case 'l': onOpenList(); break;
                case 'o': case 'Enter': if (focused) redirect('show', 'hits', focused.id); break;
                case 'Escape': onClose(); break;
                case '?': setHelp(h => !h); break;
                default:
                    if (KEY_ACTION[e.key] && DECIDE_ACTIONS.includes(KEY_ACTION[e.key])) setAction(KEY_ACTION[e.key]);
            }
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, [action, rows.length, focused, onClose, onOpenList, redirect]);

    return (
        <Paper variant="outlined" sx={{ p: 1.5 }}>
            <Stack direction="row" spacing={1} alignItems="flex-start" flexWrap="wrap" useFlexGap>
                <Box flex={1} minWidth={0}>
                    <Typography variant="subtitle1">{item.label || item.key}</Typography>
                    <Typography variant="body2" color="text.secondary">
                        {fmtNum(item.n_open)} open of {fmtNum(item.n)} hits · {pluralize(item.projects, 'project')}
                        {item.groups && item.groups.length ? ` (${item.groups.join(', ')}${item.projects > item.groups.length ? ', …' : ''})` : ''}
                        {' · '}{fmtPct(item.in_main_share)} in main · {fmtNum(item.new_7d)} new in 7 d
                        {item.rule_name ? ` · rule ${item.rule_name}` : ''}{item.severity_max ? ` · ${item.severity_max}` : ''}
                    </Typography>
                    {item.questions > 0 && (
                        <Typography variant="body2" color="info.main">
                            {pluralize(item.questions, 'question')} of the harness model inside: a decision on the cluster skips them,{' '}
                            <Link to={listUrl('hits', { ...queueFilter('questions'), cluster: item.cluster, view: 'list' })}>answer them first</Link>.
                        </Typography>
                    )}
                    {item.fields && item.fields.length > 0 && (
                        <Typography variant="caption" color="text.secondary" component="div">
                            Fields: {item.fields.slice(0, 20).join(', ')}{item.fields.length > 20 ? ` … ${item.fields.length - 20} more` : ''}
                        </Typography>
                    )}
                </Box>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                    {DECIDE_ACTIONS.map(a => (
                        <Button key={a} size="small" variant={a === 'confirm' ? 'contained' : 'outlined'}
                                label={`${reviewActionLabels[a]} (${Object.keys(KEY_ACTION).find(k => KEY_ACTION[k] === a)})`} onClick={() => setAction(a)} />
                    ))}
                    <Button size="small" label={`Open ${fmtNum(item.n_open)} as a list (l)`} onClick={onOpenList} />
                    <Button size="small" label="? keys" onClick={() => setHelp(h => !h)} />
                    <IconButton size="small" onClick={onClose} aria-label="Close the cluster"><CloseIcon fontSize="small" /></IconButton>
                </Stack>
            </Stack>
            <Collapse in={help}>
                <Paper variant="outlined" sx={{ p: 1, my: 1 }}>
                    <SimpleTable rows={CLUSTER_KEYS.map(([k, v]) => ({ k, v }))} rowKey={r => r.k}
                                 columns={[{ label: 'Key', source: 'k' }, { label: 'Action', source: 'v' }]} />
                </Paper>
            </Collapse>
            <Grid container spacing={1} sx={{ mt: 1 }}>
                <Grid item xs={12} md={5}>
                    <Typography variant="subtitle2">Sample ({rows.length} of {fmtNum(item.n)}, newest first)</Typography>
                    <Loaded state={samples} skeleton={3}>
                        {() => (
                            <Table size="small">
                                <TableBody>
                                    {rows.map((r, i) => (
                                        <TableRow key={r.id} hover selected={i === cursor} onClick={() => setCursor(i)} sx={{ cursor: 'pointer' }}>
                                            <TableCell sx={{ minWidth: 0 }}>
                                                <Typography variant="body2">{subjectOf(r)}</Typography>
                                                <Typography variant="caption" color="text.secondary">{r.project_path}</Typography>
                                            </TableCell>
                                            <TableCell><StatusChip status={r.status} /></TableCell>
                                            <TableCell><PresenceChip hit={r} /></TableCell>
                                            <TableCell><Link to={showUrl('hits', r.id)}>page</Link></TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        )}
                    </Loaded>
                </Grid>
                <Grid item xs={12} md={7}>
                    <Paper variant="outlined" sx={{ p: 1.5, overflowX: 'auto' }}>
                        <EvidencePanel hitId={focused ? focused.id : null} onAction={() => {}} />
                    </Paper>
                </Grid>
            </Grid>
            {action && (
                <DecideDialog action={action} filter={decideFilter} title={clusterTitle(item)} onClose={() => setAction(null)}
                              onDone={() => onClose(true)} />
            )}
        </Paper>
    );
};

// GET /hits/clusters under the view's filters: the groups of open hits with counts and samples; a row opens the
// cluster panel, "Decide" the decision dialog, "list" the flat list filtered to the cluster.
const ClusterBoard = ({ counts }) => {
    const dataProvider = useDataProvider();
    const { filterValues, setFilters, displayedFilters } = useListContext();
    const { scope } = useScope();
    const [by, setBy] = useState(readClusterBy);
    const [pages, setPages] = useState([]);           // the loaded pages of clusters
    const [after, setAfter] = useState(null);
    const [open, setOpen] = useState(null);           // the cluster of the panel
    const [decide, setDecide] = useState(null);       // { action, item }
    const filter = apiFilterOf(filterValues);
    const filterKey = JSON.stringify(filter);
    const state = useFetch(() => dataProvider.hitsClusters({ by, filter, limit: 25, after }), [by, filterKey, after, scope]);
    useEffect(() => { setPages([]); setAfter(null); setOpen(null); }, [by, filterKey, scope]);
    useEffect(() => {
        if (!state.data) return;
        setPages(prev => (after ? [...prev, state.data] : [state.data]));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [state.data]);
    const changeBy = (e, v) => { if (!v) return; setBy(v); try { localStorage.setItem(CLUSTER_BY_KEY, v); } catch (err) { /* ignore */ } };
    const items = pages.flatMap(p => p.items || []);
    const last = pages[pages.length - 1] || state.data;
    const openList = item => setFilters({ ...filterValues, cluster: item.cluster, view: 'list' }, displayedFilters);
    const reloadAll = () => { setPages([]); setAfter(null); state.reload(); counts.reload(); };
    const n = counts.data && counts.data.counts;
    const tab = tabOf(filterValues);
    return (
        <Box p={1}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
                <Typography variant="body2" color="text.secondary">Group by:</Typography>
                <ToggleButtonGroup size="small" exclusive value={by} onChange={changeBy} aria-label="Cluster by">
                    {CLUSTER_BY.map(([id, label, hint]) => (
                        <ToggleButton key={id} value={id}><Tooltip title={hint}><span>{label}</span></Tooltip></ToggleButton>
                    ))}
                </ToggleButtonGroup>
                <Box flex={1} />
                {n && QUEUE_TABS.includes(tab) && (
                    <Typography variant="body2" color="text.secondary">
                        {fmtEstimate(n[tab], false)} open hits{last ? ` in ${fmtNum(last.total_clusters)} clusters` : ''}
                    </Typography>
                )}
                {last && <AsOf value={last.computed_at} snapshot={false} prefix="clusters" />}
            </Stack>
            {open && (
                <Box mb={1}>
                    <ClusterPanel item={open} filter={filter} onClose={changed => { setOpen(null); if (changed === true) reloadAll(); }}
                                  onOpenList={() => openList(open)} />
                </Box>
            )}
            <Loaded state={pages.length ? { data: true } : state} skeleton={6}>
                {() => (
                    <Box sx={{ overflowX: 'auto' }}>
                        <Table size="small">
                            <TableHead>
                                <TableRow>
                                    <TableCell>Cluster</TableCell>
                                    <TableCell>Rule</TableCell>
                                    <TableCell align="right">Open</TableCell>
                                    <TableCell align="right">Projects</TableCell>
                                    <TableCell>Groups</TableCell>
                                    <TableCell align="right">In main</TableCell>
                                    <TableCell align="right">New 7 d</TableCell>
                                    <TableCell align="right">Questions</TableCell>
                                    <TableCell>Severity</TableCell>
                                    <TableCell />
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {items.map(item => (
                                    <TableRow key={item.cluster} hover selected={open && open.cluster === item.cluster}
                                              onClick={() => setOpen(item)} sx={{ cursor: 'pointer' }}>
                                        <TableCell sx={{ maxWidth: 420 }}>
                                            <Clipped text={item.label || item.key} max={90} component="div" />
                                            <Typography variant="caption" color="text.secondary">
                                                {item.object_type || ''}{item.field_name ? ` · field ${item.field_name}` : ''}{item.group ? ` · ${item.group}` : ''}
                                            </Typography>
                                        </TableCell>
                                        <TableCell><Clipped text={item.rule_name || (item.rule_id ? `#${item.rule_id}` : '-')} max={30} /></TableCell>
                                        <TableCell align="right"><b>{fmtNum(item.n_open)}</b>{item.n !== item.n_open ? <Typography variant="caption" color="text.secondary"> / {fmtNum(item.n)}</Typography> : null}</TableCell>
                                        <TableCell align="right">{fmtNum(item.projects)}</TableCell>
                                        <TableCell><Clipped text={(item.groups || []).join(', ')} max={40} /></TableCell>
                                        <TableCell align="right">{fmtPct(item.in_main_share)}</TableCell>
                                        <TableCell align="right">{fmtNum(item.new_7d)}</TableCell>
                                        <TableCell align="right">{item.questions ? <Chip size="small" color="info" label={item.questions} /> : 0}</TableCell>
                                        <TableCell>{item.severity_max || '-'}</TableCell>
                                        <TableCell sx={{ whiteSpace: 'nowrap' }} onClick={e => e.stopPropagation()}>
                                            <Button size="small" label="Decide" onClick={() => setDecide({ action: 'confirm', item })} />
                                            <Button size="small" label="list" onClick={() => openList(item)} />
                                        </TableCell>
                                    </TableRow>
                                ))}
                                {!items.length && (
                                    <TableRow><TableCell colSpan={10}>
                                        <Typography variant="body2" color="text.secondary">No open hit for these filters. Try another tab or scope.</Typography>
                                    </TableCell></TableRow>
                                )}
                            </TableBody>
                        </Table>
                        {last && (
                            <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
                                <TruncatedNote shown={items.length} total={last.total_clusters} what="clusters" />
                                {last.truncated && (
                                    <Typography variant="caption" color="warning.main">
                                        More than {fmtNum(last.scanned)} hits matched: only these were clustered. Narrow the filter (a rule, the scope).
                                    </Typography>
                                )}
                                {last.next_cursor && <Button size="small" label="Load more clusters" disabled={state.loading} onClick={() => setAfter(last.next_cursor)} />}
                            </Stack>
                        )}
                    </Box>
                )}
            </Loaded>
            {decide && (
                <DecideDialog action={decide.action} filter={{ ...filter, cluster: decide.item.cluster }} title={clusterTitle(decide.item)}
                              onClose={() => setDecide(null)} onDone={reloadAll} />
            )}
            <Box mt={2}>
                <DetailsSection title="Recent decisions by filter" count="undo">
                    <RecentBatches />
                </DetailsSection>
            </Box>
        </Box>
    );
};

// ---- the page ----------------------------------------------------------------------------------------------------

const parseFilter = search => {
    try {
        const raw = new URLSearchParams(search).get('filter');
        return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
};

const Body = ({ counts, view }) => (view === 'clusters' ? <ClusterBoard counts={counts} /> : <Triage />);

// The cluster board of the open hits is the default view; the Questions tab (and a deep link with view=list) opens
// the flat list. The counts of every tab come from one aggregate; they reload after a decision, not on every page.
export const HitList = () => {
    const { scope } = useScope();
    const location = useLocation();
    const urlFilter = parseFilter(location.search);
    const current = urlFilter || tabFilter('todecide');
    const view = viewOf(current);
    const counts = useTabCounts(current, scope);
    const timer = useRef(null);
    const [batch, setBatch] = useState(null);
    const review = useMemo(() => ({
        bump: () => { clearTimeout(timer.current); timer.current = setTimeout(() => counts.reload(), 2000); },
        announce: setBatch,
    }), [counts.reload]);   // eslint-disable-line react-hooks/exhaustive-deps
    return (
        <ReviewContext.Provider value={review}>
            <List filters={filters} filterDefaultValues={tabFilter('todecide')} perPage={25} storeKey={false}
                  pagination={view === 'list' ? <ScalePagination /> : false}
                  sort={{ field: 'first_seen_at', order: 'ASC' }} title={scopedTitle('Review', scope)}
                  queryOptions={{ enabled: view === 'list' }}>
                <QueueTabs counts={counts} />
                <Body counts={counts} view={view} />
            </List>
            <UndoSnackbar batch={batch} onClose={() => setBatch(null)} />
        </ReviewContext.Provider>
    );
};

// ---- hit page --------------------------------------------------------------------------------------------------

const ReviewActions = () => {
    const record = useRecordContext();
    const [action, setAction] = useState(null);
    if (!record) return null;
    return (
        <TopToolbar>
            {allowedOf(record).map(a => (
                <Button key={a} label={reviewActionLabels[a]} onClick={() => setAction(a)} />
            ))}
            <Button label="Back to review" component={Link} to={listUrl('hits', openQueueFilter({ view: 'list' }))} />
            {action && <ReviewDialog action={action} record={record} onClose={() => setAction(null)} />}
        </TopToolbar>
    );
};

const HitTitle = () => {
    const r = useRecordContext();
    return <span>Hit {r ? `${subjectOf(r)} · ${statusLabel(r.status)}` : ''}</span>;
};

// the verdict history of a hit (hit_verdicts): the last verdict of every rule version with its diff, then every change
const fmtValue = v => (v === null || v === undefined ? '-' : (Array.isArray(v) ? v.join(', ') : String(v)));

export const HitHistory = ({ hitId }) => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.hitHistory({ id: hitId }), [hitId]);
    return (
        <Loaded state={state}>
            {h => (
                <Stack spacing={2}>
                    <Box>
                        <Typography variant="subtitle2">Per rule version (the last verdict of each)</Typography>
                        <SimpleTable rows={h.versions} rowKey={v => v.rule_version} empty="No history yet" columns={[
                            { label: 'Version', render: v => `v${v.rule_version}` },
                            { label: 'Verdict', render: v => <StatusChip status={v.status} /> },
                            { label: 'Decided by', render: v => tierLabel(v.decided_tier) },
                            { label: 'Prompts / model', render: v => `${v.prompt_version || '-'} / ${v.model || '-'}` },
                            { label: 'Reason', render: v => <Clipped text={v.reason || ''} max={160} /> },
                            { label: 'Changed vs previous version', render: v => (v.diff_to_previous_version
                                ? Object.entries(v.diff_to_previous_version).map(([k, [a, b]]) => `${k}: ${fmtValue(a)} → ${fmtValue(b)}`).join('; ') || 'same verdict'
                                : '') },
                            { label: 'At', render: v => fmtDate(v.at) },
                        ]} />
                    </Box>
                    <Box>
                        <Typography variant="subtitle2">Every change (newest first){h.truncated ? ' - truncated' : ''}</Typography>
                        <SimpleTable rows={h.items} rowKey={i => i.id} empty="No history yet" columns={[
                            { label: 'At', render: i => fmtDate(i.created_at) },
                            { label: 'Verdict', render: i => <StatusChip status={i.status} /> },
                            { label: 'Version', render: i => `v${i.rule_version}` },
                            { label: 'Who', render: i => [tierLabel(i.decided_tier), i.reviewer || i.verifier_model || i.model].filter(Boolean).join(': ') },
                            { label: 'Source', render: i => [i.source, i.rollout_id && `rollout #${i.rollout_id}`, i.batch_id && `batch #${i.batch_id}`].filter(Boolean).join(' · ') },
                            { label: 'Changed', render: i => (i.previous
                                ? i.changed.filter(k => !k.endsWith('_hash')).map(k => `${k}: ${fmtValue(i.previous[k])} → ${fmtValue(i[k])}`).join('; ')
                                : 'first verdict') },
                        ]} />
                    </Box>
                </Stack>
            )}
        </Loaded>
    );
};

const HitEvidence = () => {
    const r = useRecordContext();
    const [tab, setTab] = useState('evidence');
    if (!r) return null;
    return (
        <Box p={2}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
                <Typography variant="h6">
                    {subjectOf(r)}
                    <Typography component="span" variant="body2" color="text.secondary"> · <Link to={projectLink(r)}>{r.project_path}</Link></Typography>
                </Typography>
                <PresenceChip hit={r} />
            </Stack>
            <Tabs value={tab} onChange={(e, v) => setTab(v)} sx={{ mb: 1 }}>
                <Tab value="evidence" label="Evidence" />
                <Tab value="history" label="History" />
            </Tabs>
            {tab === 'evidence' ? <Evidence detail={r} /> : <HitHistory hitId={r.id} />}
        </Box>
    );
};

export const HitShow = () => (
    <Show actions={<ReviewActions />} title={<HitTitle />}>
        <HitEvidence />
    </Show>
);
