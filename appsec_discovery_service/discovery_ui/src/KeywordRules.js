import React from 'react';
import {
    List, Datagrid, TextField, BooleanField, EditButton, FunctionField, Link,
    Create, Edit, SimpleForm, TextInput, SelectInput, BooleanInput, required, useRecordContext,
    ArrayInput, SimpleFormIterator, NumberInput,
} from 'react-admin';
import { Box, Chip, Stack, Typography } from '@mui/material';
import { severityChoices, actionChoices, parserChoices, modeLabel, openQueueFilter as openFilter } from './choices';
import { TagsInput } from './TagsInput';
import { RuleFormToolbar, RuleStatsAside } from './RuleTools';
import { listUrl } from './common';

// Keyword rules: the list says in words what a rule matches (matcherPhrase); the form has the same four sections as the
// LLM form (What / Scope / Behaviour / Field combination).

const modeChoices = ['auto', 'review'].map(id => ({ id, name: modeLabel(id) }));

const filters = [
    <TextInput source="q" label="Search" alwaysOn />,
    <SelectInput source="severity" choices={severityChoices} />,
    <SelectInput source="mode" choices={modeChoices} />,
    <BooleanInput source="include_deleted" label="Show deleted" />,
];

// "tables named *user* · fields *inn|passport* · projects grp/*"
export const matcherPhrase = r => {
    if (r.builtin === 'core') return 'built-in keyword scoring';
    const parts = [];
    const what = r.object_type_re ? `${r.object_type_re} objects` : 'objects';
    if (r.object_re) parts.push(`${what} named *${r.object_re}*`);
    else if (r.object_type_re) parts.push(what);
    if (r.field_re) parts.push(`fields *${r.field_re}*`);
    if (r.field_type_re) parts.push(`field types *${r.field_type_re}*`);
    if (r.fields_all && r.fields_all.length) {
        const n = r.min_groups ? `${r.min_groups} of ${r.fields_all.length}` : 'all';
        parts.push(`fields for ${n} of: ${r.fields_all.join(' + ')}`);
    }
    if (r.fields_none && r.fields_none.length) parts.push(`but no field *${r.fields_none.join('|')}*`);
    if (r.parser) parts.push(`parser ${r.parser}`);
    if (r.project_re) parts.push(`projects ${r.project_re}`);
    return parts.join(' · ') || 'everything';
};

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

export const KeywordRuleList = () => (
    <List filters={filters} sort={{ field: 'id', order: 'ASC' }} title="Keyword rules">
        <Datagrid rowClick="edit" bulkActionButtons={false}>
            <FunctionField label="Name" sortBy="name" render={() => <NameCell />} />
            <FunctionField label="Matches" sortable={false} render={r => <Typography variant="body2">{matcherPhrase(r)}</Typography>} />
            <FunctionField label="Category / severity" sortBy="category" render={r => `${r.category || '-'}${r.severity ? ` / ${r.severity}` : ''}`} />
            <FunctionField label="Mode" sortBy="mode" render={r => <Chip size="small" variant="outlined" label={modeLabel(r.mode)} />} />
            <TextField source="action" label="Action" sortable={false} />
            <BooleanField source="enabled" label="Enabled" />
            <FunctionField label="Open hits" sortable={false} render={r => (r.pending_hits
                ? <Link to={listUrl('hits', openFilter({ rule_id: r.id }))} onClick={e => e.stopPropagation()}>{r.pending_hits}</Link> : 0)} />
            <EditButton />
        </Datagrid>
    </List>
);

// At least one matcher; a category unless the rule only excludes.
const validateRule = (values) => {
    const errors = {};
    const groups = (values.fields_all || []).filter(g => g && g.trim());
    const excluded = (values.fields_none || []).filter(g => g && g.trim());
    if (!['parser', 'object_re', 'object_type_re', 'field_re', 'field_type_re'].some(k => values[k]) && !groups.length) {
        errors.object_re = 'Set at least one of parser, object, object type, field, field type or a field combination';
    }
    if (groups.length && (values.field_re || values.field_type_re)) {
        errors.field_re = 'A field combination is an object rule: leave field / field type empty';
    }
    if (excluded.length && !groups.length) {
        errors.fields_none = 'Needs a field combination';
    }
    if (values.min_groups && (!groups.length || values.min_groups > groups.length)) {
        errors.min_groups = `Between 1 and ${groups.length || 0} (the number of field groups)`;
    }
    if (values.action !== 'exclude' && !values.category) {
        errors.category = 'Required unless the action is exclude';
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

const KeywordRuleForm = ({ builtin }) => (
    <SimpleForm validate={builtin ? undefined : validateRule} toolbar={<RuleFormToolbar kind="keyword" />}>
        {builtin ? (
            <>
                <TextField source="name" />
                <SelectInput source="mode" choices={modeChoices} validate={required()} />
                <BooleanInput source="enabled" />
                <TagsInput />
            </>
        ) : (
            <>
                <Section n="1" title="What">
                    <TextInput source="name" validate={required()} fullWidth />
                    <TextInput source="category" helperText="Tag of the hits, e.g. pii, auth, finance" />
                    <SelectInput source="severity" choices={severityChoices} defaultValue="medium" validate={required()} />
                    <TagsInput />
                </Section>
                <Section n="2" title="Scope" hint="Regex or substring on the stored objects; every set matcher must match.">
                    <TextInput source="project_re" label="Project" fullWidth helperText="e.g. grp/.* or payments" />
                    <TextInput source="parser" helperText={`Exact parser name: ${parserChoices.join(', ')} or an external one (e.g. mssql)`} />
                    <TextInput source="object_re" label="Object name" fullWidth helperText="e.g. user|client|customer" />
                    <TextInput source="object_type_re" label="Object type" fullWidth helperText="e.g. table, rpc, query|mutation" />
                    <TextInput source="field_re" label="Field name" fullWidth
                               helperText="e.g. inn|passport. A field matcher makes it a field rule (one hit per matching field)" />
                    <TextInput source="field_type_re" label="Field type" fullWidth helperText="e.g. varchar|text" />
                </Section>
                <Section n="3" title="Behaviour">
                    <SelectInput source="mode" choices={modeChoices} defaultValue="auto" validate={required()}
                                 helperText="Review: every hit waits for a human. Auto: hits match at once" />
                    <SelectInput source="action" choices={actionChoices} defaultValue="score" validate={required()}
                                 helperText="Exclude: the hit suppresses the other rules' hits on the object" />
                    <BooleanInput source="enabled" defaultValue={true} />
                </Section>
                <Section n="4" title="Field combination" hint="An object rule: the object needs a field for each group (or for min groups), and none of the exceptions.">
                    <ArrayInput source="fields_all" label="Field groups">
                        <SimpleFormIterator inline disableReordering>
                            <TextInput source="" label="Field group (regex, case-insensitive, e.g. last_?name|fio)"
                                       helperText={false} fullWidth />
                        </SimpleFormIterator>
                    </ArrayInput>
                    <NumberInput source="min_groups" label="Groups needed (empty: all)" min={1}
                                 helperText="e.g. 2 of 3: last name, passport, birth date" />
                    <ArrayInput source="fields_none" label="No field may match (exceptions, e.g. masked)">
                        <SimpleFormIterator inline disableReordering>
                            <TextInput source="" label="Field regex" helperText={false} fullWidth />
                        </SimpleFormIterator>
                    </ArrayInput>
                </Section>
            </>
        )}
    </SimpleForm>
);

const KeywordRuleTitle = () => {
    const r = useRecordContext();
    return <span>Keyword rule {r ? `"${r.name}" (v${r.version})` : ''}</span>;
};

const EditForm = () => {
    const r = useRecordContext();
    return <KeywordRuleForm builtin={r && r.builtin === 'core'} />;
};

export const KeywordRuleEdit = () => (
    <Edit title={<KeywordRuleTitle />} mutationMode="pessimistic" aside={<RuleStatsAside />}>
        <EditForm />
    </Edit>
);

export const KeywordRuleCreate = () => (
    <Create redirect="list" title="New keyword rule">
        <KeywordRuleForm builtin={false} />
    </Create>
);
