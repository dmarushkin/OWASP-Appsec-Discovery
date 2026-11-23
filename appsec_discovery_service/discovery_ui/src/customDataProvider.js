import { fetchUtils, HttpError } from 'react-admin';
import simpleRestProvider from 'ra-data-simple-rest';
import { stringify } from 'query-string';
import { getToken } from './authProvider';

const apiUrl = '/api';

// FastAPI puts the error text in `detail` (a string, or pydantic's list of {loc, msg});
// fetchJson only reads `message`, so without this every error reads "Bad Request".
export const errorMessage = (body, fallback) => {
    const detail = body && body.detail;
    if (Array.isArray(detail)) {
        return detail.map(d => `${(d.loc || []).filter(p => p !== 'body').join('.')}: ${d.msg}`).join('; ');
    }
    return (typeof detail === 'string' && detail) || fallback;
};

// Authorization header only when a valid token exists (no more "Bearer null", P3-2)
const httpClient = (url, options = {}) => {
    if (!options.headers) {
        options.headers = new Headers({ Accept: 'application/json' });
    }
    const token = getToken();
    if (token) {
        options.headers.set('Authorization', `Bearer ${token}`);
    }
    return fetchUtils.fetchJson(url, options).catch(error => {
        if (error instanceof HttpError) {
            throw new HttpError(errorMessage(error.body, error.message), error.status, error.body);
        }
        throw error;
    });
};

const baseProvider = simpleRestProvider(apiUrl, httpClient);

const post = (path, data, method = 'POST') =>
    httpClient(`${apiUrl}${path}`, { method, body: JSON.stringify(data || {}) }).then(({ json }) => ({ data: json }));

const get = (path, query) =>
    httpClient(`${apiUrl}${path}${query ? '?' + stringify(query, { skipNull: true }) : ''}`).then(({ json }) => ({ data: json }));

const del = (path, query) =>
    httpClient(`${apiUrl}${path}${query ? '?' + stringify(query, { skipNull: true }) : ''}`, { method: 'DELETE' })
        .then(({ json }) => ({ data: json }));

const enc = encodeURIComponent;

// ---------------------------------------------------------------- GitLab group scope (scope bar)

// The scope bar (Layout.js) sets the current GitLab group; every hits / objects / projects list and every aggregate,
// cluster and decision filter gets it as `group=<prefix>` unless the filter names a group itself.
const SCOPED_RESOURCES = ['hits', 'objects', 'projects'];
let currentScope = '';
export const setCurrentScope = value => { currentScope = value || ''; };
export const getCurrentScope = () => currentScope;
export const withScope = (filter, resource) => {
    const f = { ...(filter || {}) };
    if (currentScope && !f.group && (!resource || SCOPED_RESOURCES.includes(resource))) f.group = currentScope;
    return f;
};

// filter keys that steer the UI only (the view mode of Review): never sent to the API
const UI_ONLY_KEYS = ['view'];
const apiFilter = (filter, resource) => {
    const f = withScope(filter, resource);
    UI_ONLY_KEYS.forEach(k => delete f[k]);
    return f;
};

// ---------------------------------------------------------------- lists: estimated totals and keyset cursors

// What the last page of each list answered besides the rows: the total is an estimate (X-Total-Estimate), the
// cursor of the next page (X-Next-Cursor). Keyed by resource + filter + sort + page size, so a page request can
// continue from the cursor of the previous page (one index probe instead of a deep OFFSET) whenever the user pages
// forward; a jump to a far page without a cursor falls back to the offset.
const listMeta = {};
const metaKey = (resource, params) =>
    `${resource}|${JSON.stringify(params.filter || {})}|${JSON.stringify(params.sort || {})}|${params.pagination.perPage}`;
export const getListMeta = (resource, params) => listMeta[metaKey(resource, params)] || null;

const PLAIN_LISTS = ['tokens', 'ingest'];     // a plain array (no Content-Range, no sort)

const getList = (resource, params) => {
    if (PLAIN_LISTS.includes(resource)) {
        const query = resource === 'ingest' ? { ...params.filter, limit: 500 } : null;
        return get(`/${resource}`, query).then(({ data }) => ({ data, total: data.length }));
    }
    const { page, perPage } = params.pagination;
    const { field, order } = params.sort || {};
    const key = metaKey(resource, params);
    const meta = listMeta[key] || (listMeta[key] = { cursors: {} });
    const filter = apiFilter(params.filter, resource);
    const cursor = page > 1 ? meta.cursors[page - 1] : null;
    const query = {
        sort: JSON.stringify([field || 'id', order || 'ASC']),
        range: JSON.stringify(cursor ? [0, perPage - 1] : [(page - 1) * perPage, page * perPage - 1]),
        filter: JSON.stringify(cursor ? { ...filter, after: cursor } : filter),
    };
    return httpClient(`${apiUrl}/${resource}?${stringify(query)}`).then(({ headers, json }) => {
        const range = headers.get('content-range');
        const total = range ? parseInt(range.split('/').pop(), 10) : json.length;
        meta.estimate = headers.get('x-total-estimate') === 'true';
        meta.total = total;
        meta.at = Date.now();
        const next = headers.get('x-next-cursor');
        if (next) meta.cursors[page] = next; else delete meta.cursors[page];
        return { data: json, total: Number.isNaN(total) ? json.length : total };
    });
};

// GET with an ETag: `{ data, etag, notModified }`; a 304 answers `notModified: true` and no data (the caller keeps
// what it has). Used for the statistics snapshots (overview, jobs/health, scan_progress, llm_progress, llm_quality).
const getSnapshot = (path, query, etag) => {
    const headers = new Headers({ Accept: 'application/json' });
    if (etag) headers.set('If-None-Match', etag);
    const token = getToken();
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const url = `${apiUrl}${path}${query ? '?' + stringify(query, { skipNull: true }) : ''}`;
    return fetch(url, { headers }).then(response => {
        if (response.status === 304) return { notModified: true, etag };
        return response.text().then(body => {
            let json = null;
            try { json = body ? JSON.parse(body) : null; } catch (e) { json = null; }
            if (response.status < 200 || response.status >= 300) {
                throw new HttpError(errorMessage(json, response.statusText || `HTTP ${response.status}`), response.status, json);
            }
            return { data: json, etag: response.headers.get('etag') || null };
        });
    });
};

const dataProvider = {
    ...baseProvider,
    getList,
    // the headers of the last page of a list: { estimate, total, cursors } (see getListMeta)
    listMeta: getListMeta,
    // an exact count of a list filter (the total of the lists is an estimate above 10 000 rows)
    exactCount: (resource, { filter, sort }) => httpClient(`${apiUrl}/${resource}?${stringify({
        sort: JSON.stringify([(sort && sort.field) || 'id', (sort && sort.order) || 'ASC']), range: JSON.stringify([0, 0]),
        filter: JSON.stringify({ ...apiFilter(filter, resource), exact: true }),
    })}`).then(({ headers }) => ({ data: parseInt((headers.get('content-range') || '/0').split('/').pop(), 10) })),
    // a statistics snapshot with an ETag (304 when unchanged): { data, etag, notModified }
    snapshot: ({ path, query, etag }) => getSnapshot(path, query, etag),
    // review a hit: { action: confirm | reject | request_info | reopen, category?, severity?, note? }
    review: (resource, { id, data }) => post(`/${resource}/${enc(id)}/review`, data),
    // the same action on up to 50 hits: { hit_ids, action, note (required), category?, severity?, dry_run }
    reviewBulk: ({ data }) => post('/hits/review_bulk', data),
    // counts of hits by dimensions (GET /hits/aggregate): by = ['queue', 'rule_id', ...], filter as GET /hits
    hitsAggregate: ({ by, filter, live } = {}) => get('/hits/aggregate', {
        by: (by || ['queue']).join(','), filter: JSON.stringify(apiFilter(filter, 'hits')), live: live ? true : null,
    }),
    // clusters of the filtered hits (GET /hits/clusters): by = schema | field_pattern | object_name | rule_group
    hitsClusters: ({ by, filter, limit, after } = {}) => get('/hits/clusters', {
        by: by || 'schema', filter: JSON.stringify(apiFilter(filter, 'hits')), limit: limit || 25, after,
    }),
    // one decision on every hit of a filter (POST /hits/decide): dry run first, then apply with expected_total
    decideHits: ({ data }) => post('/hits/decide', { ...data, filter: apiFilter(data.filter, 'hits') }),
    undoDecision: ({ id }) => post(`/hits/decide/${enc(id)}/undo`),
    reviewBatches: ({ limit = 20, reviewer } = {}) => get('/review_batches', { limit, reviewer }),
    reviewBatch: ({ id }) => get(`/review_batches/${enc(id)}`),
    // autocompletes: rules by name (GET /rules?q=), categories, object types, GitLab groups
    rules: ({ q, kind, limit = 20, includeDisabled = true } = {}) =>
        get('/rules', { q: q || null, kind, limit, include_disabled: includeDisabled }),
    categories: () => get('/categories'),
    objectTypes: () => get('/object_types'),
    groups: ({ q, depth = 2, parent, limit = 200 } = {}) => get('/groups', { q: q || null, depth, parent, limit }),
    // the project page (GET /projects/{id}): the list row plus hits by rule, objects by type, open MRs, last jobs
    project: ({ id, detail = true }) => get(`/projects/${enc(id)}`, { detail }),
    // parse projects again: { project_ids?: [...], parsers?: [...], mains, mrs, llm, force } (POST /projects/parse)
    parse: (resource, { data }) => post(`/${resource}/parse`, data),
    // run LLM rules over projects already parsed: { rule_ids, project_ids?: [...], mrs, executor } (POST /llm_rules/run)
    runRules: (resource, { data }) => post(`/${resource}/run`, data),
    // project scan mode: { scan_mode: 'rules' | 'inventory', parse }
    setScanMode: (resource, { id, data }) => post(`/${resource}/${enc(id)}`, data, 'PATCH'),
    // what a rule would hit: { kind, rule } (new) or { rule_id, rule: patch }, project_ids?, sample
    dryRun: ({ data }) => post('/rules/dry_run', data),
    // per rule and version: hits by status and the precision of human decisions
    ruleStats: ({ ruleId, since }) => get('/rules/stats', { rule_id: ruleId, since }),
    // landscape: matches by category / project / type, open counts; narrowed by the optional filters
    overview: ({ projectId, category, tag, ruleId, severity } = {}) =>
        get('/overview', { project_id: projectId, category, tag, rule_id: ruleId, severity }),
    jobStats: () => get('/jobs/stats'),
    // LLM rule runs with progress: { active: [...], recent: [...] }
    llmRuns: () => get('/llm_runs'),
    // queue health: per kind pending / running / failed, oldest pending age, workers, LLM throughput + ETA
    jobsHealth: () => get('/jobs/health'),
    // failed jobs of the last `hours`, grouped by kind and error prefix (GET /jobs/errors)
    jobErrors: ({ hours = 24 } = {}) => get('/jobs/errors', { hours }),
    // a failed job back to the queue; a waiting job out of it
    retryJob: ({ id }) => post(`/jobs/${enc(id)}/retry`),
    cancelJob: ({ id }) => post(`/jobs/${enc(id)}/cancel`),
    // harness work: runs answered by a harness model (GET /llm_work/jobs), work items by purpose / sample / owner
    // (GET /llm_work/stats)
    llmWorkJobs: ({ active = true, limit = 50 } = {}) => get('/llm_work/jobs', { active, limit }),
    llmWorkStats: () => get('/llm_work/stats'),
    // pending service LLM runs become harness runs under the same job id: { job_id?, limit }
    takeOver: ({ data }) => post('/llm_work/take_over', data),
    // the unanswered rest of a harness run back to the service: { job_id, all_unanswered: true }
    releaseRun: ({ jobId }) => post('/llm_work/release', { job_id: jobId, all_unanswered: true }),
    // parse scan progress: { main, by_scan_mode, mrs, external, queue, projects: { total, items } }
    scanProgress: (query = {}) => get('/scan_progress', query),
    // LLM rule coverage: { rules, main, mrs, queue, last_computed_at, projects: { total, items } }
    llmProgress: (query = {}) => get('/llm_progress', query),
    // manual label of an object or one of its fields: { category, severity, field_name?, note?, tags? }
    setLabel: ({ id, data }) => post(`/objects/${enc(id)}/labels`, data),
    removeLabel: ({ id, fieldName }) => del(`/objects/${enc(id)}/labels`, fieldName ? { field_name: fieldName } : null),
    // the same label on up to 50 objects / fields: { items: [{ object_id, field_name? }], category, severity, tags?, note?, dry_run }
    labelBulk: ({ data }) => post('/objects/labels', data),
    // tiered workflow: service vs harness agreement per LLM rule, backlog, questions (GET /llm_quality)
    llmQuality: ({ ruleId } = {}) => get('/llm_quality', { rule_id: ruleId }),
    llmRuleErrors: ({ ruleId, hours } = {}) => get(`/llm_rules/${enc(ruleId)}/errors`, { hours }),
    // subjects where a human / the harness model disagrees with the service model (source: human | verification)
    mislabeled: ({ ruleId, source }) => get(`/llm_rules/${enc(ruleId)}/mislabeled`, { source, limit: 50 }),
    // prompt trials of an LLM rule and one trial with its items; a new trial of a candidate prompt on the service
    // model: { prompt, sample?, from_mislabeled?, include_controls?, rerun_current?, note? } (202, status queued)
    trials: ({ ruleId }) => get(`/llm_rules/${enc(ruleId)}/trials`),
    trial: ({ id }) => get(`/prompt_trials/${enc(id)}`),
    createTrial: ({ ruleId, data }) => post(`/llm_rules/${enc(ruleId)}/trials`, data),
    // prompt proposals: per rule, open ones across all rules, re-ask cost (dry run), accept (human only: version
    // bump) / reject
    proposals: ({ ruleId }) => get(`/llm_rules/${enc(ruleId)}/proposals`),
    openProposals: ({ limit = 50 } = {}) => get('/prompt_proposals', { status: 'open', limit }),
    proposalReask: ({ id }) => get(`/prompt_proposals/${enc(id)}/reask`),
    acceptProposal: ({ id, data }) => post(`/prompt_proposals/${enc(id)}/accept`, data),
    rejectProposal: ({ id, data }) => post(`/prompt_proposals/${enc(id)}/reject`, data),
    // LLM rule lifecycle: versions (list, candidate, estimate, activate / rollback / discard: humans only), rollouts,
    // the verdict history of a hit
    ruleVersions: ({ ruleId }) => get(`/llm_rules/${enc(ruleId)}/versions`),
    createVersion: ({ ruleId, data }) => post(`/llm_rules/${enc(ruleId)}/versions`, data),
    versionEstimate: ({ id }) => get(`/llm_rule_versions/${enc(id)}/estimate`),
    activateVersion: ({ id, data }) => post(`/llm_rule_versions/${enc(id)}/activate`, data),
    rollbackVersion: ({ id, data }) => post(`/llm_rule_versions/${enc(id)}/rollback`, data),
    discardVersion: ({ id, data }) => post(`/llm_rule_versions/${enc(id)}/discard`, data),
    rollouts: (query = {}) => get('/llm_rollouts', query),
    rollout: ({ id }) => get(`/llm_rollouts/${enc(id)}`),
    rolloutAction: ({ id, action, data }) => post(`/llm_rollouts/${enc(id)}/${enc(action)}`, data),
    hitHistory: ({ id }) => get(`/hits/${enc(id)}/history`),
    // revoke a service token (the row stays, revoked_at is set)
    revokeToken: ({ id }) => del(`/tokens/${enc(id)}`),
};

export default dataProvider;
