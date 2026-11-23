import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Pagination, useDataProvider, useGetList, useListContext } from 'react-admin';
import { Link as RouterLink } from 'react-router-dom';
import { getListMeta } from './customDataProvider';
import {
    Accordion, AccordionDetails, AccordionSummary, Alert, Autocomplete, Box, Button, Card, CardContent, CardHeader, Chip,
    Grid, LinearProgress, Link, Paper, Skeleton, Stack, Table, TableBody, TableCell, TableHead, TableRow,
    TextField as MuiTextField, Tooltip, Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {
    HEALTH_COLORS, STATUS_COLORS, healthLabel, llmStateLabel, openStatuses, presenceHint, presenceLabel, presenceOf,
    scanStateLabel, statusHint, statusLabel, tierLabel,
} from './choices';

// The glossary (choices.js) is the single source of every label; it is re-exported here so a page can import the
// words next to the helpers (scanStateLabel / llmStateLabel keep their old import path this way too).
export * from './choices';

// react-admin URLs: a list with a filter (listUrl('hits', { rule_id: 3 })) and a show page
export const listUrl = (resource, filter) => `/${resource}?filter=${encodeURIComponent(JSON.stringify(filter))}`;
export const showUrl = (resource, id) => `/${resource}/${encodeURIComponent(id)}/show`;

// ---------------------------------------------------------------- formats (sec. 2.5)

const pad2 = n => String(n).padStart(2, '0');
const toDate = value => (value === null || value === undefined || value === '' ? null : new Date(value));
const sameDay = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// "HH:mm" today, "d MMM HH:mm" otherwise (another year adds it); the full date belongs in a title (see DateText)
export const fmtDate = value => {
    const d = toDate(value);
    if (!d || Number.isNaN(d.getTime())) return '';
    const now = new Date();
    const time = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
    if (sameDay(d, now)) return time;
    const year = d.getFullYear() === now.getFullYear() ? '' : ` ${d.getFullYear()}`;
    return `${d.getDate()} ${MONTHS[d.getMonth()]}${year} ${time}`;
};
// the full locale date for titles / tooltips
export const fmtFullDate = value => {
    const d = toDate(value);
    return d && !Number.isNaN(d.getTime()) ? d.toLocaleString() : '';
};
export const DateText = ({ value, empty = '-' }) => (value
    ? <span title={fmtFullDate(value)}>{fmtDate(value)}</span>
    : <span>{empty}</span>);

// "just now" / "2 min ago" / "3 h ago" / "2 d ago"; a future date reads "in 13 h"
export const fmtAgo = (value, now = new Date()) => {
    const d = toDate(value);
    if (!d || Number.isNaN(d.getTime())) return '';
    const diff = Math.round((now.getTime() - d.getTime()) / 1000);
    const abs = Math.abs(diff);
    let text;
    if (abs < 60) text = diff < 0 ? '1 min' : 'just now';
    else if (abs < 3600) text = `${Math.floor(abs / 60)} min`;
    else if (abs < 86400) text = `${Math.floor(abs / 3600)} h`;
    else text = `${Math.floor(abs / 86400)} d`;
    if (text === 'just now') return text;
    return diff < 0 ? `in ${text}` : `${text} ago`;
};
export const Ago = ({ value, empty = '-' }) => (value
    ? <span title={fmtFullDate(value)}>{fmtAgo(value)}</span>
    : <span>{empty}</span>);

export const fmtPct = value => (value === null || value === undefined ? '-' : `${Math.round(value * 100)}%`);
export const shortSha = value => (value ? String(value).slice(0, 10) : '');
// seconds -> "2h 05m", "45s", "3d 4h"
export const fmtDuration = seconds => {
    if (seconds === null || seconds === undefined) return '-';
    const s = Math.max(0, Math.round(seconds));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (d >= 1) return `${d}d ${h % 24}h`;
    if (h >= 1) return `${h}h ${String(m % 60).padStart(2, '0')}m`;
    return `${m}m`;
};
export const fmtNum = value => (value === null || value === undefined ? '-' : Number(value).toLocaleString());
// pluralize(3, 'job') -> "3 jobs"; pluralize(1, 'query', 'queries') -> "1 query"
export const pluralize = (n, noun, plural) => `${fmtNum(n)} ${Number(n) === 1 ? noun : (plural || `${noun}s`)}`;

// One way of clipping long text: a single ellipsis and the full text in a tooltip.
export const Clipped = ({ text, max = 120, component = 'span', ...rest }) => {
    const value = text === null || text === undefined ? '' : String(text);
    if (value.length <= max) return <Box component={component} {...rest}>{value}</Box>;
    return (
        <Tooltip title={value} placement="top-start">
            <Box component={component} {...rest}>{`${value.slice(0, Math.max(0, max - 1)).trimEnd()}…`}</Box>
        </Tooltip>
    );
};

const cell = value => {
    if (value === null || value === undefined) return '';
    if (Array.isArray(value)) return value.join(', ');
    if (typeof value === 'boolean') return value ? 'yes' : 'no';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
};

// ---------------------------------------------------------------- data loading

// Run one async call, again when `deps` change or reload() is called: { data, error, loading, reload, at }.
// reload() returns a promise that settles when the new answer is in (useAutoRefresh waits for it); the call runs
// at most once at a time - a reload during a request is queued behind it, never fired in parallel.
export const useFetch = (fn, deps) => {
    const [state, setState] = useState({ loading: true });
    const [tick, setTick] = useState(0);
    const waiters = useRef([]);
    const running = useRef(false);
    useEffect(() => {
        let alive = true;
        running.current = true;
        setState(s => ({ ...s, loading: true }));
        const settle = ok => {
            running.current = false;
            const w = waiters.current;
            waiters.current = [];
            w.forEach(r => r(ok));
        };
        fn().then(({ data }) => { if (alive) setState({ data, loading: false, at: Date.now() }); settle(true); })
            .catch(error => { if (alive) setState(s => ({ data: s.data, error, loading: false, at: s.at })); settle(false); });
        return () => { alive = false; };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [...deps, tick]);
    const reload = useCallback(() => new Promise(resolve => {
        waiters.current.push(resolve);
        if (!running.current) setTick(t => t + 1);
    }), []);
    return { ...state, reload };
};

// A statistics snapshot (GET /overview, /jobs/health, /scan_progress, /llm_progress, /llm_quality, /hits/aggregate):
// the same shape as useFetch plus `computedAt` / `snapshot` (from the body) and an ETag: a reload sends
// If-None-Match and a 304 keeps the data (the server answers 304 until the scanner's next refresh).
export const useSnapshot = (path, query, deps = []) => {
    const dataProvider = useDataProvider();
    const etag = useRef(null);
    const last = useRef(null);
    const state = useFetch(() => dataProvider.snapshot({ path, query, etag: etag.current }).then(r => {
        if (r.notModified) return { data: last.current };
        etag.current = r.etag;
        last.current = r.data;
        return { data: r.data };
    }), deps);
    const d = state.data;
    return { ...state, computedAt: d && d.computed_at, snapshot: !!(d && d.snapshot) };
};

// Loading / error state of a useFetch call; renders children once data is there. `skeleton` (true or a row count)
// draws fixed-height rows instead of a spinner so a panel keeps its place; an error shows an inline Retry.
export const Loaded = ({ state, children, skeleton = 3, height = 28 }) => {
    if (state.error) {
        return (
            <Alert severity="error" action={state.reload
                ? <Button color="inherit" size="small" onClick={state.reload}>Retry</Button> : null}>
                {state.error.message || 'Request failed'}
            </Alert>
        );
    }
    if (state.loading && state.data === undefined) {
        const rows = skeleton === true ? 3 : Number(skeleton) || 0;
        if (!rows) return <Skeleton variant="rounded" height={height} aria-label="Loading" />;
        return (
            <Stack spacing={1} aria-label="Loading" aria-busy="true">
                {Array.from({ length: rows }, (_, i) => <Skeleton key={i} variant="rounded" height={height} />)}
            </Stack>
        );
    }
    return children(state.data);
};

// Re-run `reload` every `ms` while `active`. The next run is scheduled only after the previous answer is in
// (`reload` may return a promise, as useFetch.reload does; false / a rejection counts as an error), the interval is
// four times longer while the tab is hidden, and it doubles after each error (up to 16x) until a run succeeds.
export const useAutoRefresh = (active, reload, ms = 5000) => {
    const fn = useRef(reload);
    fn.current = reload;
    useEffect(() => {
        if (!active) return undefined;
        let timer = null;
        let stopped = false;
        let errors = 0;
        const delay = () => ms * Math.min(16, 2 ** errors) * (typeof document !== 'undefined' && document.hidden ? 4 : 1);
        const schedule = () => { if (!stopped) timer = setTimeout(run, delay()); };
        const run = () => {
            if (stopped) return;
            let result;
            try { result = fn.current(); } catch (e) { result = Promise.resolve(false); }
            Promise.resolve(result).then(ok => { errors = ok === false ? errors + 1 : 0; }, () => { errors += 1; })
                .then(schedule);
        };
        const onVisible = () => { if (!document.hidden && timer) { clearTimeout(timer); schedule(); } };
        document.addEventListener('visibilitychange', onVisible);
        schedule();
        return () => { stopped = true; clearTimeout(timer); document.removeEventListener('visibilitychange', onVisible); };
    }, [active, ms]);
};

// "updated 32 s ago" of a snapshot (computed_at) with a tick every 10 s; `snapshot` false reads "computed now".
export const AsOf = ({ value, snapshot = true, prefix = 'updated' }) => {
    const [, setTick] = useState(0);
    useEffect(() => {
        const timer = setInterval(() => setTick(t => t + 1), 10000);
        return () => clearInterval(timer);
    }, []);
    if (!value) return null;
    const s = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
    const text = s < 90 ? `${s} s ago` : fmtAgo(value);
    return (
        <Tooltip title={`${snapshot ? 'Statistics snapshot computed' : 'Computed live'} ${fmtFullDate(value)}`}>
            <Typography component="span" variant="caption" color="text.secondary">{prefix} {text}{snapshot ? '' : ' (live)'}</Typography>
        </Tooltip>
    );
};

// "~12.4k" for an estimated total, the exact figure otherwise
export const fmtEstimate = (n, estimate) => (n === null || n === undefined ? '-' : `${estimate ? '~' : ''}${fmtNum(n)}`);

// Never a silent cut: "top 25 of 1 240" / "first 200 of ~5 000" when a list or an aggregate was truncated.
export const TruncatedNote = ({ shown, total, truncated, estimate = false, what = 'rows', hint, sx }) => {
    const cut = truncated || (total !== null && total !== undefined && shown < total);
    if (!cut) return null;
    const text = total !== null && total !== undefined && total > shown
        ? `${fmtNum(shown)} of ${fmtEstimate(total, estimate)} ${what} shown`
        : `top ${fmtNum(shown)} ${what} shown${truncated ? ' (more exist)' : ''}`;
    return (
        <Typography variant="caption" color="text.secondary" component="div" sx={sx}>
            {text}{hint ? ` · ${hint}` : ''}
        </Typography>
    );
};

// Where a hit's code is (rule_hits.in_main / in_open_mr): In main / Only in open MR / Gone. Neutral chips.
export const PresenceChip = ({ hit, value, ...rest }) => {
    const p = value || presenceOf(hit);
    if (!p) return null;
    return (
        <Tooltip title={presenceHint(p)}>
            <Chip size="small" variant="outlined" label={presenceLabel(p)}
                  color={p === 'gone' ? 'default' : 'default'} sx={p === 'gone' ? { opacity: 0.7 } : undefined} {...rest} />
        </Tooltip>
    );
};

// ---------------------------------------------------------------- tables and chips

// A small read-only table for rows without ids: columns = [{ label, source | render(row) }].
export const SimpleTable = ({ columns, rows, empty = 'Nothing here', rowKey }) => {
    if (!rows || !rows.length) return <Typography variant="body2" color="text.secondary">{empty}</Typography>;
    return (
        <Table size="small">
            <TableHead>
                <TableRow>{columns.map(c => <TableCell key={c.label}>{c.label}</TableCell>)}</TableRow>
            </TableHead>
            <TableBody>
                {rows.map((row, i) => (
                    <TableRow key={rowKey ? rowKey(row) : i}>
                        {columns.map(c => (
                            <TableCell key={c.label}>{c.render ? c.render(row) : cell(row[c.source])}</TableCell>
                        ))}
                    </TableRow>
                ))}
            </TableBody>
        </Table>
    );
};

export const TagChips = ({ tags }) => (
    <Stack direction="row" spacing={0.5} flexWrap="wrap" component="span">
        {(tags || []).map(t => <Chip key={t} label={t} size="small" />)}
    </Stack>
);

// Generic glossary chip: `map` = labels (object or function), `color` = colour map; coloured chips are filled,
// neutral ones outlined (colour means a hit status or a failure, nothing else).
export const LabelChip = ({ map, color, value, title, variant, ...rest }) => {
    if (value === null || value === undefined || value === '') return <span>-</span>;
    const label = typeof map === 'function' ? map(value) : ((map && map[value]) ?? String(value));
    const chipColor = (color && color[value]) || 'default';
    const chip = <Chip size="small" label={label} color={chipColor}
                       variant={variant || (chipColor === 'default' ? 'outlined' : 'filled')} {...rest} />;
    return title ? <Tooltip title={title}><span>{chip}</span></Tooltip> : chip;
};

export const StatusChip = ({ status, ...rest }) => (
    <LabelChip map={statusLabel} color={STATUS_COLORS} value={status} title={statusHint(status)} {...rest} />
);

const isOpen = hit => !!hit && openStatuses.includes(hit.status);

// Who decided a hit: a neutral outlined chip; hidden while the hit is open (see OpenHint).
export const TierChip = ({ hit, ...rest }) => {
    if (!hit || isOpen(hit) || !hit.decided_tier) return null;
    return <Chip size="small" variant="outlined" label={tierLabel(hit.decided_tier)} {...rest} />;
};

// What an open hit waits for (replaces the tier chip): a caption.
export const openHintText = hit => {
    if (!isOpen(hit)) return null;
    if (hit.asked_by_model) return 'Asked by the harness model';
    if (hit.status === 'need_more_info') return 'Service model unsure';
    return 'Waits for review';
};
export const OpenHint = ({ hit, ...rest }) => {
    const text = openHintText(hit);
    return text ? <Typography variant="caption" color="text.secondary" component="span" {...rest}>{text}</Typography> : null;
};

// A verdict of an older rule version, kept and scoring until the rule's rollout asks the model again.
export const StaleChip = ({ hit }) => {
    if (!hit || !hit.stale) return null;
    const versions = hit.rule_version
        ? ` (v${hit.rule_version}${hit.current_rule_version ? ` → v${hit.current_rule_version}` : ''})` : '';
    return (
        <Tooltip title={`${hit.stale_reason || 'an older rule version'}: kept and scoring until the rule rollout asks the model again`}>
            <Chip size="small" variant="outlined" label={`stale${versions}`} />
        </Tooltip>
    );
};

export const HealthChip = ({ health, ...rest }) => <LabelChip map={healthLabel} color={HEALTH_COLORS} value={health} {...rest} />;

// Effective filters of a view as removable chips: items = [{ id, label }].
export const FilterChips = ({ items, onRemove }) => {
    const list = (items || []).filter(Boolean);
    if (!list.length) return null;
    return (
        <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap component="span">
            {list.map(item => (
                <Chip key={item.id ?? item.label} size="small" variant="outlined" label={item.label}
                      onDelete={onRemove && !item.fixed ? () => onRemove(item.id ?? item.label, item) : undefined} />
            ))}
        </Stack>
    );
};

// ---------------------------------------------------------------- home-page building blocks

const LEVEL_COLORS = { ok: 'success.main', info: 'info.main', warning: 'warning.main', error: 'error.main' };

// One fact: a coloured dot, one number, two short lines and (optionally) a link. `level` = ok | info | warning | error.
// `tone` / `sub` / `linkLabel` are accepted as aliases of `level` / `sub1` / a "→ label" link to `to` (the Work desk
// used them while StatTile did not know them: the dots were always green and the captions missing).
export const StatTile = ({ title, value, sub1, sub2, level, tone, sub, linkLabel, to, action, minWidth = 150 }) => {
    const lvl = level || tone || 'ok';
    const line1 = sub1 !== undefined ? sub1 : sub;
    const link = action || (linkLabel && to
        ? <Link component={RouterLink} to={to} variant="caption" underline="hover">→ {linkLabel}</Link> : null);
    return (
        <Paper variant="outlined" sx={{ p: 1.5, minWidth, flex: '1 1 0', display: 'flex', flexDirection: 'column', gap: 0.25 }}>
            <Stack direction="row" spacing={0.75} alignItems="center">
                <Box component="span" aria-label={lvl}
                     sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: LEVEL_COLORS[lvl] || LEVEL_COLORS.ok, flexShrink: 0 }} />
                <Typography variant="overline" color="text.secondary" sx={{ lineHeight: 1.6 }} noWrap>{title}</Typography>
            </Stack>
            <Typography variant="h5" component="div">
                {to ? <Link component={RouterLink} to={to} underline="hover" color="inherit">{value ?? '-'}</Link> : (value ?? '-')}
            </Typography>
            {line1 !== undefined && line1 !== null && <Typography variant="caption" color="text.secondary" noWrap component="div">{line1}</Typography>}
            {sub2 !== undefined && sub2 !== null && <Typography variant="caption" color="text.secondary" noWrap component="div">{sub2}</Typography>}
            {link && <Box sx={{ mt: 0.5 }}>{link}</Box>}
        </Paper>
    );
};

// The card of the home pages: title, an optional action on the right; `md` = grid width inside a <Grid container>.
export const Panel = ({ title, md = 12, action, children, sx }) => (
    <Grid item xs={12} md={md}>
        <Card variant="outlined" sx={{ height: '100%', ...sx }}>
            {(title || action) && (
                <CardHeader title={title} titleTypographyProps={{ variant: 'subtitle1' }} action={action}
                            sx={{ pb: 0, '& .MuiCardHeader-action': { alignSelf: 'center', m: 0 } }} />
            )}
            <CardContent sx={{ pt: 1, '&:last-child': { pb: 2 } }}>{children}</CardContent>
        </Card>
    </Grid>
);

// A collapsed section with a count badge in its header; the content mounts on first open (its data loads then).
export const DetailsSection = ({ title, count, children, defaultOpen = false, sx }) => {
    const [open, setOpen] = useState(defaultOpen);
    const badge = count === undefined || count === null ? null : count;
    return (
        <Accordion variant="outlined" disableGutters expanded={open} onChange={(e, v) => setOpen(v)}
                   TransitionProps={{ unmountOnExit: true }} sx={{ '&:before': { display: 'none' }, ...sx }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="subtitle1">{title}</Typography>
                    {badge !== null && <Chip size="small" variant="outlined" label={typeof badge === 'number' ? fmtNum(badge) : badge} />}
                </Stack>
            </AccordionSummary>
            <AccordionDetails>{children}</AccordionDetails>
        </Accordion>
    );
};

// ---------------------------------------------------------------- prompt trials

// GET /prompt_trials metrics: { targets: { fixed, newly_wrong, still_wrong, accuracy_before, accuracy_after },
// controls: { regressions, total }, all: { accuracy_before, accuracy_after } }; a flat object with the same keys works too.
const trialNumbers = metrics => {
    const m = metrics || {};
    const t = m.targets || m, c = m.controls || m, a = m.all || t;
    const num = v => (v === null || v === undefined ? 0 : Number(v));
    return {
        fixed: num(t.fixed), newly_wrong: num(t.newly_wrong), still_wrong: num(t.still_wrong),
        regressions: num(c.regressions), controls: num(c.total),
        before: a.accuracy_before ?? null, after: a.accuracy_after ?? null,
        empty: !m.targets && !m.controls && !('fixed' in m) && !('regressions' in m),
    };
};

// 'better' | 'worse' | 'mixed' | null (no metrics yet)
export const trialVerdict = metrics => {
    const n = trialNumbers(metrics);
    if (n.empty) return null;
    if (n.fixed > 0 && n.newly_wrong === 0 && n.regressions === 0) return 'better';
    if (n.regressions > 0 || n.newly_wrong > n.fixed) return 'worse';
    return 'mixed';
};
const VERDICT = {
    better: { text: '▲ better', color: 'success.main' },
    worse: { text: '▼ worse', color: 'error.main' },
    mixed: { text: 'mixed', color: 'text.secondary' },
};

// green = fixed, red = newly wrong / regressions, grey = still wrong, then "accuracy before -> after" and the verdict.
export const TrialMetricChips = ({ metrics, verdict = true }) => {
    const n = trialNumbers(metrics);
    if (n.empty) return <Typography variant="body2" color="text.secondary">No results yet</Typography>;
    const v = trialVerdict(metrics);
    return (
        <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" useFlexGap component="span">
            <Tooltip title="Wrong before, right with the new prompt">
                <Chip size="small" color={n.fixed ? 'success' : 'default'} variant={n.fixed ? 'filled' : 'outlined'} label={`fixed ${n.fixed}`} />
            </Tooltip>
            <Tooltip title="Right before, wrong with the new prompt">
                <Chip size="small" color={n.newly_wrong ? 'error' : 'default'} variant={n.newly_wrong ? 'filled' : 'outlined'}
                      label={`newly wrong ${n.newly_wrong}`} />
            </Tooltip>
            <Tooltip title="Controls (agreed verdicts) the new prompt changed">
                <Chip size="small" color={n.regressions ? 'error' : 'default'} variant={n.regressions ? 'filled' : 'outlined'}
                      label={`regressions ${n.regressions}${n.controls ? `/${n.controls}` : ''}`} />
            </Tooltip>
            {n.still_wrong > 0 && (
                <Tooltip title="Wrong before and still wrong">
                    <Chip size="small" variant="outlined" label={`still wrong ${n.still_wrong}`} />
                </Tooltip>
            )}
            {(n.before !== null || n.after !== null) && (
                <Typography variant="body2" component="span" sx={{ ml: 0.5 }}>{fmtPct(n.before)} → {fmtPct(n.after)}</Typography>
            )}
            {verdict && v && (
                <Typography variant="body2" component="span" sx={{ color: VERDICT[v].color, fontWeight: 500 }}>{VERDICT[v].text}</Typography>
            )}
        </Stack>
    );
};

// ---------------------------------------------------------------- pickers and progress

// Project autocomplete with a server-side search (the API pages projects by 100, so no "load all").
export const ProjectPicker = ({ value, onChange, multiple = false, label = 'Projects' }) => {
    const [q, setQ] = useState('');
    const { data = [], isLoading } = useGetList('projects', {
        pagination: { page: 1, perPage: 50 }, sort: { field: 'full_path', order: 'ASC' }, filter: q ? { q } : {},
    });
    return (
        <Autocomplete multiple={multiple} options={data} value={value} loading={isLoading} filterOptions={x => x}
                      getOptionLabel={p => (p && p.full_path) || ''} isOptionEqualToValue={(a, b) => a.id === b.id}
                      onChange={(e, v) => onChange(v)}
                      onInputChange={(e, v, reason) => reason === 'input' && setQ(v)}
                      renderInput={params => <MuiTextField {...params} label={label} size="small" margin="dense" />} />
    );
};

// Rule autocomplete with a server-side search (GET /rules?q=: both rule kinds, no "load all 500"). `value` is a rule
// id (or null); a rule that is not among the current matches (a deep link) is labelled by its id.
export const RulePicker = ({ value, onChange, label = 'Rule', kind, size = 'small', sx }) => {
    const dataProvider = useDataProvider();
    const [q, setQ] = useState('');
    const known = useRef({});
    const state = useFetch(() => dataProvider.rules({ q, kind }).then(({ data }) => {
        (data || []).forEach(r => { known.current[r.id] = r; });
        return { data: data || [] };
    }), [q, kind]);
    const options = state.data || [];
    const selected = value === null || value === undefined || value === '' ? null
        : (known.current[value] || { id: value, name: `rule #${value}` });
    const labelOf = r => `${r.name}${r.enabled === false ? ' (disabled)' : ''}${r.kind ? ` · ${r.kind}` : ''}`;
    return (
        <Autocomplete options={selected && !options.some(o => o.id === selected.id) ? [selected, ...options] : options}
                      value={selected} loading={state.loading} filterOptions={x => x} size={size} sx={{ minWidth: 220, ...sx }}
                      getOptionLabel={r => (r ? labelOf(r) : '')} isOptionEqualToValue={(a, b) => a.id === b.id}
                      onChange={(e, v) => onChange(v ? v.id : null, v)}
                      onInputChange={(e, v, reason) => reason === 'input' && setQ(v)}
                      renderInput={params => <MuiTextField {...params} label={label} size={size} margin="dense" />} />
    );
};

// Category autocomplete from GET /categories (every category a rule or a hit has), free text allowed.
export const useCategories = () => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.categories().catch(() => ({ data: { items: [] } })), []);
    return [...new Set(((state.data && state.data.items) || []).map(r => r.category).filter(Boolean))].sort();
};
export const CategoryPicker = ({ value, onChange, label = 'Category', autoFocus = false, size = 'small', sx }) => {
    const options = useCategories();
    return (
        <Autocomplete freeSolo options={options} value={value || ''} inputValue={value || ''} size={size} sx={sx}
                      onInputChange={(e, v) => onChange(v || '')} onChange={(e, v) => onChange(v || '')}
                      renderInput={params => <MuiTextField {...params} label={label} margin="dense" autoFocus={autoFocus} size={size} />} />
    );
};

// Object types of the main snapshots with counts (GET /object_types): [{ id, name }] choices
export const useObjectTypeChoices = () => {
    const dataProvider = useDataProvider();
    const state = useFetch(() => dataProvider.objectTypes().catch(() => ({ data: { items: [] } })), []);
    return ((state.data && state.data.items) || []).filter(r => r.type).map(r => ({ id: r.type, name: `${r.type} (${fmtNum(r.n)})` }));
};

// GitLab group autocomplete (GET /groups?q=): the value is a path prefix ("grp/payments") or ''.
export const GroupPicker = ({ value, onChange, label = 'Group', depth = 3, size = 'small', sx, variant, inputSx }) => {
    const dataProvider = useDataProvider();
    const [q, setQ] = useState('');
    const state = useFetch(() => dataProvider.groups({ q, depth }).then(({ data }) => ({ data: (data && data.items) || [] }))
        .catch(() => ({ data: [] })), [q, depth]);
    const options = state.data || [];
    const selected = value ? (options.find(o => o.path === value) || { path: value, projects: null }) : null;
    return (
        <Autocomplete options={selected && !options.some(o => o.path === selected.path) ? [selected, ...options] : options}
                      value={selected} loading={state.loading} filterOptions={x => x} size={size} sx={{ minWidth: 220, ...sx }}
                      getOptionLabel={g => (g ? g.path : '')} isOptionEqualToValue={(a, b) => a.path === b.path}
                      renderOption={(props, g) => (
                          <li {...props} key={g.path}>
                              <span style={{ paddingLeft: `${Math.max(0, (g.depth || 1) - 1) * 12}px` }}>{g.path}</span>
                              {g.projects !== null && g.projects !== undefined && (
                                  <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>{pluralize(g.projects, 'project')}</Typography>
                              )}
                          </li>
                      )}
                      onChange={(e, v) => onChange(v ? v.path : '')}
                      onInputChange={(e, v, reason) => reason === 'input' && setQ(v)}
                      renderInput={params => <MuiTextField {...params} label={label} size={size} margin="dense" variant={variant} sx={inputSx} />} />
    );
};

// List pagination at scale: react-admin's page control plus the truth about the total - "~N" when the API estimated
// it (X-Total-Estimate), with an "exact count" action (one count(*) on click, never per page). Pages reached by
// paging forward continue from the previous page's keyset cursor (customDataProvider).
export const ScalePagination = props => {
    const { resource, filter: permanentFilter, filterValues, sort, perPage, total, isFetching } = useListContext();
    const dataProvider = useDataProvider();
    const [exact, setExact] = useState(null);
    // the filter the list was fetched with: the user's filter values plus the List's permanent `filter` prop (e.g. the
    // group of the Group view), merged as react-admin merges them for getList
    const filter = { ...(filterValues || {}), ...(permanentFilter || {}) };
    // a plain function, not through useDataProvider(): react-admin's proxy expects every provider method to return a Promise
    const meta = getListMeta(resource, { filter, sort, pagination: { perPage } });
    const estimate = !!(meta && meta.estimate && meta.total === total);
    useEffect(() => { setExact(null); }, [resource, JSON.stringify(filter), JSON.stringify(sort)]);  // eslint-disable-line react-hooks/exhaustive-deps
    const count = () => dataProvider.exactCount(resource, { filter, sort }).then(({ data }) => setExact(data)).catch(() => setExact(null));
    return (
        <Box display="flex" alignItems="center" justifyContent="flex-end" flexWrap="wrap" gap={1}>
            {(estimate || exact !== null) && !isFetching && (
                <Typography variant="caption" color="text.secondary" component="span">
                    {exact !== null ? `exactly ${fmtNum(exact)} rows` : <>about {fmtNum(total)} rows (estimate) · <Link component="button" variant="caption" onClick={count}>exact count</Link></>}
                </Typography>
            )}
            <Pagination rowsPerPageOptions={[25, 50, 100]} {...props} />
        </Box>
    );
};

// Result table of a dry run / apply of a bulk action (hits review, labels)
export const BulkResultTable = ({ items, idOf }) => (
    <SimpleTable rows={items} rowKey={idOf} columns={[
        { label: 'Item', render: idOf },
        { label: 'Result', source: 'result' },
        { label: 'Details', render: r => [
            r.error, r.would_be ? `${statusLabel(r.status)} -> ${statusLabel(r.would_be)}` : statusLabel(r.status),
            r.allowed && `allowed: ${r.allowed.join(', ') || 'none'}`, r.hit_id,
        ].filter(Boolean).join('; ') },
    ]} />
);

// Progress of an LLM rule run (jobs.progress / GET /llm_runs): "N of M objects" with a bar.
export const RunProgress = ({ progress, width = 220 }) => {
    const p = progress || {};
    if (p.total_objects === undefined || p.total_objects === null) return <span>-</span>;
    const total = p.total_objects || 0;
    const done = p.done_objects || 0;
    const failed = (p.failed_objects || 0) + (p.expired_objects || 0);
    const value = total ? Math.min(100, Math.round(((done + failed) / total) * 100)) : 100;
    const extra = [
        p.failed_objects ? `${p.failed_objects} failed` : '',
        p.expired_objects ? `${p.expired_objects} expired` : '',
        p.answered_objects ? `${p.answered_objects} answered` : '',
        p.leased_objects ? `${p.leased_objects} claimed by a harness` : '',
        p.skipped_objects ? `${p.skipped_objects} left to a harness model` : '',
    ].filter(Boolean).join(', ');
    return (
        <Box sx={{ width }}>
            <LinearProgress variant="determinate" value={value} aria-label={`${done} of ${total} objects processed`}
                            color={failed ? 'warning' : 'primary'} />
            <Typography variant="caption" color="text.secondary">
                {done} of {total} processed{extra ? ` (${extra})` : ''}
            </Typography>
        </Box>
    );
};

// Why objects of an LLM run failed (jobs.progress.errors, GET /jobs/{id}, /llm_runs, /llm_work/jobs):
// { total, items: [{ rule, object, object_key, field, where, error }], by_class: [{ rule, error_class, count }] }.
// `summary` is progress.error (the per-rule line of an incomplete run). Entries beyond the first ones are counted only.
export const RunErrors = ({ errors, summary, compact = false }) => {
    const e = errors || {};
    const items = e.items || [];
    const classes = e.by_class || [];
    if (!summary && !items.length && !classes.length) return null;
    const more = (e.total || 0) - items.length;
    return (
        <Stack spacing={1}>
            {summary && <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>{summary}</Typography>}
            {classes.length > 0 && (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    {classes.map((c, i) => (
                        <Chip key={i} size="small" variant="outlined" color="warning"
                              label={`${c.rule ? `${c.rule}: ` : ''}${c.error_class} (${fmtNum(c.count)})`} />
                    ))}
                </Stack>
            )}
            {items.length > 0 && !compact && (
                <SimpleTable rows={items} rowKey={r => `${r.object_key || r.object || ''}:${r.rule || ''}:${r.error}`} columns={[
                    { label: 'Rule', render: r => r.rule || '-' },
                    { label: 'Object', render: r => [r.object || r.object_key || r.where || '-', r.field && `.${r.field}`].filter(Boolean).join('') },
                    { label: 'Error', render: r => <Clipped text={r.error} max={160} /> },
                ]} />
            )}
            {items.length > 0 && compact && (
                <Typography variant="caption" color="text.secondary" component="div">
                    {items.slice(0, 3).map((r, i) => <div key={i}>{r.object || r.object_key || r.where || '-'}: <Clipped text={r.error} max={120} /></div>)}
                </Typography>
            )}
            {more > 0 && <Typography variant="caption" color="text.secondary">{fmtNum(more)} more {more === 1 ? 'failure is' : 'failures are'} counted above but not listed</Typography>}
        </Stack>
    );
};

// Parse state of a project's main branch (GET /scan_progress, /projects `scan`): a chip. Red only when failed.
const SCAN_STATE_COLORS = { current: 'success', failed: 'error', partial: 'warning' };
export const ScanStateChip = ({ scan }) => {
    if (!scan) return <span>-</span>;
    const job = scan.job === 'running' ? 'parsing' : scan.job === 'pending' ? 'parse queued' : scan.job;
    const label = scanStateLabel(scan) + (job ? ` (${job})` : '');
    const title = [
        scan.commit && `head commit ${shortSha(scan.commit)}`,
        `parsed ${shortSha(scan.scanned_commit) || 'never'}`,
        scan.synced === false && 'GitLab activity not synced yet',
        scan.last_error,
    ].filter(Boolean).join('; ');
    const color = scan.job === 'running' ? 'info' : (SCAN_STATE_COLORS[scan.state] || 'default');
    return <Chip size="small" label={label} title={title} color={color}
                 variant={scan.job || color === 'default' ? 'outlined' : 'filled'} />;
};

// LLM rule coverage of a project's main branch (GET /llm_progress, /projects `llm`): a chip. Red only when failed.
const LLM_STATE_COLORS = { current: 'success', failed: 'error' };
export const LlmStateChip = ({ llm }) => {
    if (!llm) return <span>-</span>;
    const job = llm.job === 'awaiting_answers' ? 'awaiting answers' : llm.job === 'pending' ? 'run queued' : llm.job;
    const remaining = llm.state === 'not_scanned' || llm.total === undefined ? '' : ` ${llm.answered} of ${llm.total}`;
    const label = llmStateLabel(llm) + remaining + (job ? ` (${job})` : '');
    const title = [
        ...(llm.rules || []).map(r => `${r.name}: ${r.total === null ? 'not counted' : `${r.answered} of ${r.total}`}`
            + (r.total !== null && !r.fresh ? ' (stale)' : '')),
        llm.pending_external ? `${llm.pending_external} held by a harness run` : '',
        llm.failed_subjects ? `${llm.failed_subjects} failed` : '',
        llm.last_error,
    ].filter(Boolean).join('; ');
    const color = llm.job === 'running' ? 'info' : (LLM_STATE_COLORS[llm.state] || 'default');
    return <Chip size="small" label={label} title={title} color={color}
                 variant={llm.job || color === 'default' ? 'outlined' : 'filled'} />;
};

// "N of M" with a bar
export const CountBar = ({ done, total, label, width = 320 }) => (
    <Box sx={{ width, maxWidth: '100%' }}>
        <LinearProgress variant="determinate" value={total ? Math.min(100, Math.round((done / total) * 100)) : 0}
                        aria-label={`${done} of ${total} ${label}`} />
        <Typography variant="caption" color="text.secondary">{done} of {total} {label}</Typography>
    </Box>
);
