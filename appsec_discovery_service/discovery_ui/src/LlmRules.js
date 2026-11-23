import React, { useMemo, useState } from 'react';
import {
    List, Datagrid, FunctionField, BooleanField, EditButton, DeleteButton, Link,
    Create, Edit, SimpleForm, TextInput, SelectInput, BooleanInput, AutocompleteInput, required, useRecordContext,
    FormDataConsumer, Button, SaveButton, Toolbar, useDataProvider, useNotify, useListContext, useRedirect, useRefresh,
    useSaveContext,
} from 'react-admin';
import { useFormContext } from 'react-hook-form';
import {
    Alert, Box, Chip, Dialog, DialogTitle, DialogContent, DialogActions, FormControlLabel, Checkbox, MenuItem, Radio,
    RadioGroup, Stack, TextField as MuiTextField, Typography,
} from '@mui/material';
import { severityChoices, modeLabel, targetLabel, openQueueFilter as openFilter } from './choices';
import { TagsInput } from './TagsInput';
import { ScopeCountButton, RuleStatsAside } from './RuleTools';
import { HealthChip, Loaded, ProjectPicker, listUrl, useCategories, useFetch } from './common';
import { RuleStudio, VersionCost } from './LlmRuleTiers';

// LLM rules: the list (8 columns) and the guided form in four sections (What / Scope / Behaviour / Prompt). A new rule
// starts disabled in review mode and lands in the Rule studio ▸ Trials to try the prompt first. Editing the prompt,
// target or scope of an existing rule makes a version: "Save as candidate version" (POST /llm_rules/{id}/versions) or
// "Save and activate" (PUT, the rollout re-asks the old verdicts).

const VERSIONED = ['prompt', 'target', 'project_re', 'object_re', 'object_type_re', 'field_re', 'field_type_re', 'mark_fields'];

const modeChoices = ['review', 'auto'].map(id => ({ id, name: modeLabel(id) }));
const targetChoices = ['field', 'object'].map(id => ({ id, name: targetLabel(id) }));

const filters = [
    <TextInput source="q" label="Search" alwaysOn />,
    <SelectInput source="target" choices={targetChoices} />,
    <SelectInput source="mode" choices={modeChoices} />,
    <BooleanInput source="include_deleted" label="Show deleted" />,
];

// ---- run ---------------------------------------------------------------------------------------------------------

// Run LLM rules over projects already parsed (POST /llm_rules/run): all projects or selected ones.
const RunRulesDialog = ({ open, onClose, rules }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const [scope, setScope] = useState('all');
    const [selected, setSelected] = useState([]);
    const [mrs, setMrs] = useState(false);
    const [executor, setExecutor] = useState('service');
    const [busy, setBusy] = useState(false);

    const submit = () => {
        const data = { rule_ids: rules.map(r => r.id), mrs, executor };
        if (scope === 'selected') data.project_ids = selected.map(p => p.id);
        setBusy(true);
        dataProvider.runRules('llm_rules', { data })
            .then(({ data: r }) => {
                const extra = [
                    r.already_queued.length ? `${r.already_queued.length} already queued` : '',
                    r.skipped_inventory.length ? `${r.skipped_inventory.length} inventory project(s) skipped` : '',
                ].filter(Boolean).join(', ');
                notify(`${r.queued.length} run(s) queued${extra ? ', ' + extra : ''}`, { type: 'info' });
                onClose();
            })
            .catch(error => notify(error.message || 'Run failed', { type: 'error' }))
            .finally(() => setBusy(false));
    };

    return (
        <Dialog open={open} onClose={onClose} onClick={e => e.stopPropagation()} fullWidth maxWidth="sm"
                aria-labelledby="run-rules-title">
            <DialogTitle id="run-rules-title">
                Run {rules.length === 1 ? rules[0].name : `${rules.length} LLM rules`} on parsed projects
            </DialogTitle>
            <DialogContent>
                <Typography variant="body2" gutterBottom>
                    Uses the stored snapshots (no clone, no parse). Only objects / fields without a verdict of the
                    rules' current versions are sent to the model.
                </Typography>
                <RadioGroup value={scope} onChange={e => setScope(e.target.value)}>
                    <FormControlLabel value="all" control={<Radio />} label="All projects" />
                    <FormControlLabel value="selected" control={<Radio />} label="Selected projects" />
                </RadioGroup>
                {scope === 'selected' && <ProjectPicker multiple value={selected} onChange={setSelected} />}
                <FormControlLabel label="Also open merge requests"
                                  control={<Checkbox checked={mrs} onChange={e => setMrs(e.target.checked)} />} />
                <Typography variant="subtitle2" sx={{ mt: 1 }}>Who answers</Typography>
                <RadioGroup value={executor} onChange={e => setExecutor(e.target.value)}>
                    <FormControlLabel value="service" control={<Radio />} label="Service model" />
                    <FormControlLabel value="external" control={<Radio />} label="Harness model (answers via MCP)" />
                </RadioGroup>
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                <Button label="Run" variant="contained" onClick={submit} disabled={busy || (scope === 'selected' && !selected.length)} />
            </DialogActions>
        </Dialog>
    );
};

const RunRuleButton = () => {
    const record = useRecordContext();
    const [open, setOpen] = useState(false);
    if (!record || record.deleted_at || !record.enabled) return null;
    return (
        <>
            <Button label="Run" onClick={e => { e.stopPropagation(); setOpen(true); }} />
            {open && <RunRulesDialog open onClose={() => setOpen(false)} rules={[record]} />}
        </>
    );
};

const BulkRunButton = () => {
    const { selectedIds, data = [] } = useListContext();
    const [open, setOpen] = useState(false);
    const rules = data.filter(r => selectedIds.includes(r.id) && r.enabled && !r.deleted_at);
    return (
        <>
            <Button label="Run selected" disabled={!rules.length} onClick={() => setOpen(true)} />
            {open && <RunRulesDialog open onClose={() => setOpen(false)} rules={rules} />}
        </>
    );
};

// ---- list --------------------------------------------------------------------------------------------------------

const NameCell = () => {
    const r = useRecordContext();
    if (!r) return null;
    return (
        <Stack direction="row" spacing={0.5} alignItems="center" component="span">
            <span>{r.name}</span>
            {r.deleted_at && <Chip size="small" label="deleted" variant="outlined" />}
        </Stack>
    );
};

export const LlmRuleList = () => {
    const dataProvider = useDataProvider();
    const quality = useFetch(() => dataProvider.llmQuality().catch(() => ({ data: { rules: [] } })), []);
    const health = Object.fromEntries(((quality.data && quality.data.rules) || []).map(r => [r.rule_id, r.health]));
    return (
        <List filters={filters} sort={{ field: 'id', order: 'ASC' }} title="LLM rules">
            <Datagrid rowClick="edit" bulkActionButtons={<BulkRunButton />}>
                <FunctionField label="Name" sortBy="name" render={() => <NameCell />} />
                <FunctionField label="Category / severity" sortBy="category"
                               render={r => `${r.category || '(classifier)'}${r.severity ? ` / ${r.severity}` : ''}`} />
                <FunctionField label="Target" sortBy="target" render={r => (
                    <Stack direction="row" spacing={0.5} alignItems="center" component="span">
                        <span>{targetLabel(r.target)}</span>
                        {r.mark_fields && <Chip size="small" variant="outlined" label="marks fields" />}
                    </Stack>)} />
                <FunctionField label="Mode" sortBy="mode" render={r => <Chip size="small" variant="outlined" label={modeLabel(r.mode)} />} />
                <BooleanField source="enabled" label="Enabled" />
                <FunctionField label="Open hits" sortable={false} render={r => (r.pending_hits
                    ? <Link to={listUrl('hits', openFilter({ rule_id: r.id }))} onClick={e => e.stopPropagation()}>{r.pending_hits}</Link> : 0)} />
                <FunctionField label="Health" sortable={false} render={r => (health[r.id] ? <HealthChip health={health[r.id]} /> : '-')} />
                <FunctionField label="" sortable={false} render={() => (
                    <Stack direction="row" spacing={0.5} component="span"><RunRuleButton /><EditButton /></Stack>)} />
            </Datagrid>
        </List>
    );
};

// ---- form --------------------------------------------------------------------------------------------------------

const validateRule = (values) => {
    const errors = {};
    if (values.target === 'object' && !values.category) {
        errors.category = 'An object rule needs a category';
    }
    if (values.target === 'object' && (values.field_re || values.field_type_re)) {
        errors.field_re = 'Field filters only apply to field rules';
    }
    return errors;
};

const Section = ({ n, title, hint, children }) => (
    <Box width="100%" mb={2}>
        <Typography variant="subtitle1" sx={{ mt: 1 }}>{n} {title}</Typography>
        {hint && <Typography variant="caption" color="text.secondary" component="div" sx={{ mb: 1 }}>{hint}</Typography>}
        {children}
    </Box>
);

// categories already in use (GET /categories: every category a rule or a hit has) + free text
const CategoryInput = () => {
    const names = useCategories();
    const [extra, setExtra] = useState([]);
    const choices = useMemo(() => [...new Set([...names, ...extra])].sort().map(c => ({ id: c, name: c })), [names, extra]);
    return (
        <AutocompleteInput source="category" label="Category" choices={choices} fullWidth
                           onCreate={value => { if (!value) return null; setExtra(x => [...x, value]); return { id: value, name: value }; }}
                           helperText="What the rule looks for; hits get the tag llm-<category>. Empty on a field rule: the built-in pii / finance / auth classifier" />
    );
};

const TEMPLATES = [
    { id: 'personal', name: 'Tables with personal data', text:
`You judge database tables. Answer "match" when the table stores personal data of natural persons: names, contact details,
government identifiers, document numbers, addresses, birth dates, or other data that identifies a person. Technical tables
(migrations, settings, counters, logs without personal fields) are "no_match". Name the fields that made you decide.` },
    { id: 'payload', name: 'API returning payload X', text:
`You judge API endpoints, RPC methods and GraphQL queries / mutations by their request and response types. Answer "match"
when the response returns <payload type: describe the data here>, "no_match" otherwise. Say which response fields carry
that data; answer "need_more_info" when the types do not show what the fields hold.` },
    { id: 'secrets', name: 'Secrets in config', text:
`You judge configuration objects and their fields. Answer "match" when a field holds a credential: a password, an API
token, a private key, a connection string with a secret, or a similar secret value. References to a secret store (a
variable name, a vault path) are "no_match". Name the fields.` },
];

// template select of the Prompt section: fills the textarea when it is empty (asks before replacing text)
const PromptTemplate = () => {
    const { getValues, setValue } = useFormContext();
    const [value, setV] = useState('');
    const apply = id => {
        const t = TEMPLATES.find(x => x.id === id);
        if (!t) return;
        const current = getValues('prompt');
        if (current && current.trim() && !window.confirm('Replace the current prompt with the template?')) return;
        setValue('prompt', t.text, { shouldDirty: true });
        setV(id);
    };
    return (
        <MuiTextField select label="Start from a template" value={value} onChange={e => apply(e.target.value)} size="small"
                      sx={{ minWidth: 280, mb: 1 }}>
            <MenuItem value="">(none)</MenuItem>
            {TEMPLATES.map(t => <MenuItem key={t.id} value={t.id}>{t.name}</MenuItem>)}
        </MuiTextField>
    );
};

const LlmRuleForm = ({ toolbar }) => (
    <SimpleForm validate={validateRule} toolbar={toolbar}>
        <Section n="1" title="What">
            <TextInput source="name" validate={required()} fullWidth />
            <CategoryInput />
            <SelectInput source="severity" choices={severityChoices} defaultValue="medium" validate={required()} />
            <TagsInput />
        </Section>
        <Section n="2" title="Scope" hint="Regex or substring on the stored objects; empty: everything. Count before you save.">
            <TextInput source="project_re" label="Project" fullWidth helperText="e.g. grp/.* or payments" />
            <TextInput source="object_re" label="Object name" fullWidth helperText="e.g. user|client|customer" />
            <TextInput source="object_type_re" label="Object type" fullWidth helperText="e.g. table, rpc, query|mutation" />
            <FormDataConsumer>
                {({ formData }) => formData.target !== 'object' && (
                    <>
                        <TextInput source="field_re" label="Field name" fullWidth helperText="e.g. inn|passport|phone (field rules only)" />
                        <TextInput source="field_type_re" label="Field type" fullWidth helperText="e.g. varchar|text (field rules only)" />
                    </>
                )}
            </FormDataConsumer>
            <FormDataConsumer>{({ formData }) => <ScopeCountButton kind="llm" values={formData || {}} />}</FormDataConsumer>
        </Section>
        <Section n="3" title="Behaviour">
            <SelectInput source="target" choices={targetChoices} defaultValue="field" validate={required()}
                         helperText="Field: one verdict per field in scope (the model sees the whole object). Object: one verdict for the whole object." />
            <FormDataConsumer>
                {({ formData }) => formData.target === 'object' && (
                    <BooleanInput source="mark_fields" label="Marks fields" defaultValue={false}
                                  helperText="Also hit each field the model names as making the object match (same status and reason; decided together with the object; still one model call per object)" />
                )}
            </FormDataConsumer>
            <SelectInput source="mode" choices={modeChoices} defaultValue="review" validate={required()}
                         helperText="Review: every hit waits for a human. Auto: hits match at once; the harness model QA-samples them" />
            <BooleanInput source="enabled" defaultValue={false} helperText="Off until you tried the prompt on a sample (Trials)" />
        </Section>
        <Section n="4" title="Prompt" hint="The system prompt the model gets with each object. It should name the verdicts match / no_match / need_more_info.">
            <PromptTemplate />
            <TextInput source="prompt" label="System prompt" multiline minRows={8} fullWidth />
        </Section>
    </SimpleForm>
);

// ---- toolbars ------------------------------------------------------------------------------------------------------

// the record's versioned fields: a plain Save keeps them (the form's prompt / scope changes go through the version buttons)
const keepVersioned = record => data => ({ ...data, ...Object.fromEntries(VERSIONED.map(k => [k, record[k]])) });

const versionDiff = (record, values) => {
    const diff = {};
    VERSIONED.forEach(k => {
        const a = record[k] ?? (k === 'mark_fields' ? false : null), b = values[k] ?? (k === 'mark_fields' ? false : null);
        if (k === 'mark_fields' && values.target !== 'object') return;
        if ((a === '' ? null : a) !== (b === '' ? null : b)) diff[k] = b === '' ? null : b;
    });
    return diff;
};

const CandidateButton = () => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const redirect = useRedirect();
    const refresh = useRefresh();
    const { getValues, trigger } = useFormContext();
    const [busy, setBusy] = useState(false);
    const submit = () => trigger().then(ok => {
        if (!ok) return;
        const diff = versionDiff(record, getValues());
        if (!Object.keys(diff).length) { notify('No change to the prompt, target or scope', { type: 'info' }); return; }
        setBusy(true);
        dataProvider.createVersion({ ruleId: record.id, data: diff })
            .then(({ data }) => {
                notify(`Candidate v${(data.version || data).version} saved; activate it in Versions`, { type: 'info' });
                refresh();
                redirect(`/llm_rules/${record.id}?tab=versions`);
            })
            .catch(e => notify(e.message || 'Failed', { type: 'error' }))
            .finally(() => setBusy(false));
    });
    return <Button label="Save as candidate version" onClick={submit} disabled={busy} />;
};

// Save and activate: the usual PUT (a new active version), after the re-ask estimate of the active version
const ActivateSaveButton = () => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const { save } = useSaveContext();
    const { getValues, trigger } = useFormContext();
    const [open, setOpen] = useState(false);
    const estimate = useFetch(() => (open ? dataProvider.ruleVersions({ ruleId: record.id })
        .then(({ data }) => {
            const active = (data.items || []).find(v => v.status === 'active');
            return active ? dataProvider.versionEstimate({ id: active.id }) : { data: null };
        }) : Promise.resolve({ data: undefined })), [open, record.id]);
    const diff = open ? versionDiff(record, getValues()) : {};
    const ask = () => trigger().then(ok => ok && setOpen(true));
    const confirm = () => { setOpen(false); save(getValues()); };
    return (
        <>
            <Button label="Save and activate" variant="contained" onClick={ask} />
            <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="md" aria-labelledby="activate-save-title">
                <DialogTitle id="activate-save-title">Save and activate v{record.version + 1}?</DialogTitle>
                <DialogContent>
                    {Object.keys(diff).length ? (
                        <>
                            <Typography variant="body2" gutterBottom>
                                Changed: {Object.keys(diff).join(', ')}. The new version is active at once; the machine verdicts of
                                v{record.version} stay (flagged stale) until the rollout asks them again. Human and harness decisions are kept.
                            </Typography>
                            <Loaded state={estimate}>
                                {e => (e === null ? <Typography variant="caption" color="text.secondary">No active version to estimate.</Typography>
                                    : <><Typography variant="caption" color="text.secondary">Re-ask cost, from the active version:</Typography><VersionCost estimate={e} /></>)}
                            </Loaded>
                        </>
                    ) : <Alert severity="info">The prompt, target and scope are unchanged: a plain Save is enough.</Alert>}
                </DialogContent>
                <DialogActions>
                    <Button label="Cancel" onClick={() => setOpen(false)} />
                    <Button label="Save and activate" variant="contained" onClick={confirm} disabled={!Object.keys(diff).length} />
                </DialogActions>
            </Dialog>
        </>
    );
};

const EditToolbar = () => {
    const record = useRecordContext();
    return (
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
            <SaveButton label="Save" transform={keepVersioned(record)} variant="outlined" />
            <CandidateButton />
            <ActivateSaveButton />
            <Box ml="auto"><DeleteButton mutationMode="pessimistic" confirmTitle="Delete LLM rule (its hits are kept)" /></Box>
        </Toolbar>
    );
};

const CreateToolbar = () => <Toolbar><SaveButton label="Save" /></Toolbar>;

const LlmRuleTitle = () => {
    const r = useRecordContext();
    return <span>LLM rule {r ? `"${r.name}" (v${r.version})` : ''}</span>;
};

// mark_fields only applies to object rules: a hidden checkbox of a field rule is not sent as set
const transform = data => ({ ...data, mark_fields: data.target === 'object' && !!data.mark_fields });

// Rule studio: Definition (the form + statistics) / Versions / Health & quality / Mislabelled / Trials / Proposals / Runs
// (LlmRuleTiers.js); `?tab=proposals` opens a tab directly (links from the Work desk).
export const LlmRuleEdit = () => (
    <Edit title={<LlmRuleTitle />} mutationMode="pessimistic" transform={transform}>
        <RuleStudio form={<LlmRuleForm toolbar={<EditToolbar />} />} aside={<RuleStatsAside />} actions={<RunRuleButton />} />
    </Edit>
);

// a new rule lands in the studio's Trials tab: try the prompt first, then enable it
export const LlmRuleCreate = () => (
    <Create redirect={(resource, id) => `/${resource}/${id}?tab=trials&created=1`} transform={transform} title="New LLM rule">
        <LlmRuleForm toolbar={<CreateToolbar />} />
    </Create>
);
