import React, { useState } from 'react';
import {
    List, Datagrid, TextField, NumberField, FunctionField, Link, Show, TextInput, SelectInput, AutocompleteInput,
    ReferenceInput, NullableBooleanInput, Button, TopToolbar, useRecordContext, useDataProvider, useNotify, useRefresh,
    useListContext, useUnselectAll,
} from 'react-admin';
import {
    Box, Chip, Dialog, DialogActions, DialogContent, DialogTitle, MenuItem, Stack, TextField as MuiTextField, Tooltip,
    Typography,
} from '@mui/material';
import { severityChoices, objectPresenceChoices, parserChoices, presenceHint, statusLabel, STATUS_COLORS } from './choices';
import {
    BulkResultTable, CategoryPicker, Clipped, PresenceChip, ScalePagination, SimpleTable, TagChips, listUrl, showUrl,
    useObjectTypeChoices,
} from './common';
import { scopedTitle, useScope } from './scope';

// Objects (the inventory): filters, manual labels (a match hit of the manual:labels rule) on an object or a field.

const BULK_MAX = 50;

// object types of the main snapshots with counts (GET /object_types)
const TypeFilter = props => <SelectInput {...props} choices={useObjectTypeChoices()} />;

// where the listed version of an object is: a main branch, or only an open MR (`source` of the row)
const SourceChip = ({ source }) => {
    if (!source) return null;
    if (source === 'orphan') return <Tooltip title="No live branch has this version any more"><Chip size="small" variant="outlined" label="Gone" sx={{ opacity: 0.7 }} /></Tooltip>;
    return <PresenceChip value={source === 'main' ? 'main' : 'mr'} />;
};

const filters = [
    <TextInput source="q" label="Object name / file" alwaysOn />,
    <ReferenceInput source="project_id" reference="projects" alwaysOn>
        <AutocompleteInput optionText="full_path" filterToQuery={q => ({ q })} label="Project" />
    </ReferenceInput>,
    <SelectInput source="presence" choices={objectPresenceChoices} emptyText="Main branches" alwaysOn />,
    <TypeFilter source="type" label="Object type" />,
    <SelectInput source="parser" label="Parser" choices={parserChoices.map(p => ({ id: p, name: p }))} />,
    <TextInput source="tag" label="Tag" />,
    <TextInput source="project_glob" label="Project glob (grp/*)" />,
    <TextInput source="field" label="Has field (substring)" />,
    <TextInput source="fields_all" label="Has field matching (regex)" />,
    <TextInput source="fields_none" label="No field matching (regex)" />,
    <TextInput source="field_type" label="Field type (substring)" />,
    <TextInput source="comment" label="Code comment (substring)" />,
    <NullableBooleanInput source="labelled" label="Labelled by hand" />,
    <NullableBooleanInput source="has_open_hits" label="Has open hits" />,
    <NullableBooleanInput source="decided" label="Has human decisions" />,
];

const SeveritySelect = ({ value, onChange }) => (
    <MuiTextField select label="Severity" value={value} onChange={e => onChange(e.target.value)} fullWidth margin="dense">
        {severityChoices.map(c => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
    </MuiTextField>
);

// Manual label (a match hit of the manual:labels rule) on one object / field, or the same label on
// several (POST /objects/labels: dry run, then apply). items: [{ object_id, field_name? }]
const LabelDialog = ({ title, items, initial = {}, onClose, onDone }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const [category, setCategory] = useState(initial.category || '');
    const [severity, setSeverity] = useState(initial.severity || 'medium');
    const [tags, setTags] = useState((initial.tags || []).join(', '));
    const [note, setNote] = useState(initial.note || '');
    const [preview, setPreview] = useState(null);
    const [busy, setBusy] = useState(false);
    const bulk = items.length > 1;

    const payload = () => ({
        category: category.trim(), severity, note: note.trim() || null,
        tags: tags.split(',').map(t => t.trim()).filter(Boolean),
    });
    const done = message => {
        notify(message, { type: 'info' });
        onDone();
        onClose();
    };
    const fail = e => notify(e.message || 'Label failed', { type: 'warning' });
    const submit = dryRun => {
        setBusy(true);
        const call = bulk
            ? dataProvider.labelBulk({ data: { ...payload(), items, dry_run: dryRun } })
                .then(({ data: r }) => (dryRun ? setPreview(r) : done(`${r.changed} object(s) / field(s) labelled`)))
            : dataProvider.setLabel({ id: items[0].object_id, data: { ...payload(), field_name: items[0].field_name || null } })
                .then(() => done('Labelled'));
        call.catch(fail).finally(() => setBusy(false));
    };
    const ok = preview ? preview.items.filter(i => i.result === 'ok').length : 0;

    return (
        <Dialog open onClose={onClose} fullWidth maxWidth={bulk ? 'md' : 'sm'} aria-labelledby="label-title">
            <DialogTitle id="label-title">{title}</DialogTitle>
            <DialogContent>
                <CategoryPicker value={category} onChange={v => { setCategory(v); setPreview(null); }} label="Category (required, e.g. pii)"
                                autoFocus size="medium" />
                <SeveritySelect value={severity} onChange={setSeverity} />
                <MuiTextField label="Tags set on the object (comma separated)" value={tags} fullWidth margin="dense"
                              onChange={e => setTags(e.target.value)} />
                <MuiTextField label="Note" value={note} onChange={e => setNote(e.target.value)} fullWidth multiline minRows={2}
                              margin="dense" />
                {preview && (
                    <Box mt={2}>
                        <Typography variant="subtitle2">Dry run: {ok} of {preview.items.length} can be labelled</Typography>
                        <BulkResultTable items={preview.items} idOf={i => `${i.object_id}${i.field_name ? '.' + i.field_name : ''}`} />
                    </Box>
                )}
            </DialogContent>
            <DialogActions>
                <Button label="Cancel" onClick={onClose} />
                {bulk && <Button label="Dry run" onClick={() => submit(true)} disabled={busy || !category.trim()} />}
                <Button label="Label" variant="contained" onClick={() => submit(false)} disabled={busy || !category.trim() || (bulk && !ok)} />
            </DialogActions>
        </Dialog>
    );
};

const BulkLabelButton = () => {
    const { selectedIds } = useListContext();
    const refresh = useRefresh();
    const unselectAll = useUnselectAll('objects');
    const [open, setOpen] = useState(false);
    const tooMany = selectedIds.length > BULK_MAX;
    return (
        <>
            <Button label="Label selected" disabled={tooMany} onClick={() => setOpen(true)} />
            {tooMany && <Typography variant="caption" color="error">At most {BULK_MAX} objects per bulk label</Typography>}
            {open && (
                <LabelDialog title={`Label ${selectedIds.length} object(s)`} items={selectedIds.map(id => ({ object_id: id }))}
                             onClose={() => setOpen(false)} onDone={() => { unselectAll(); refresh(); }} />
            )}
        </>
    );
};

const ProjectCell = () => {
    const r = useRecordContext();
    if (!r) return null;
    return r.project_id
        ? <Link to={showUrl('projects', r.project_id)} onClick={e => e.stopPropagation()}>{r.project_path}</Link>
        : <span>{r.project_path}</span>;
};

export const ObjectList = () => {
    const { scope } = useScope();
    return (
        <List filters={filters} sort={{ field: 'name', order: 'ASC' }} title={scopedTitle('Objects', scope)} perPage={50}
              pagination={<ScalePagination />}>
            <Datagrid rowClick="show" bulkActionButtons={<BulkLabelButton />}>
                <TextField source="name" />
                <TextField source="type" />
                <TextField source="parser" />
                <ProjectCell label="Project" sortable={false} />
                <TextField source="file" />
                <NumberField source="fields" />
                <NumberField source="labels" label="Manual labels" />
                <FunctionField label="Tags" render={r => <TagChips tags={r.tags} />} />
                <FunctionField label="Where" sortable={false} render={r => <SourceChip source={r.source} />} />
            </Datagrid>
        </List>
    );
};

// a hit of the object; the presence suffix when the row carries the stored flags (hits only in an open MR, or gone)
const presenceSuffix = h => (h.in_main === undefined ? '' : (h.in_main ? '' : (h.in_open_mr ? ' · only in open MR' : ' · gone')));
const HitChip = ({ hit }) => (
    <Tooltip title={hit.in_main === undefined ? '' : presenceHint(hit.in_main ? 'main' : (hit.in_open_mr ? 'mr' : 'gone'))}>
        <Chip component={Link} to={showUrl('hits', hit.id)} clickable size="small" color={STATUS_COLORS[hit.status] || 'default'}
              variant={hit.kind === 'manual' ? 'filled' : 'outlined'}
              label={`${hit.kind === 'manual' ? 'label' : hit.rule}: ${hit.category || '?'} ${hit.severity || ''} (${statusLabel(hit.status)})${presenceSuffix(hit)}`} />
    </Tooltip>
);

const LabelActions = ({ object, fieldName, hits, onChange }) => {
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const [open, setOpen] = useState(false);
    const manual = (hits || []).find(h => h.kind === 'manual');
    const remove = () => dataProvider.removeLabel({ id: object.id, fieldName })
        .then(() => { notify('Label removed', { type: 'info' }); onChange(); })
        .catch(e => notify(e.message || 'Remove failed', { type: 'warning' }));
    const subject = `${object.name}${fieldName ? '.' + fieldName : ''}`;
    return (
        <Stack direction="row" spacing={1} component="span">
            <Button label={manual ? 'Relabel' : 'Label'} size="small" onClick={() => setOpen(true)} />
            {manual && <Button label="Remove label" size="small" onClick={remove} />}
            {open && (
                <LabelDialog title={`Label ${subject}`} items={[{ object_id: object.id, field_name: fieldName || null }]}
                             initial={manual || {}} onClose={() => setOpen(false)} onDone={onChange} />
            )}
        </Stack>
    );
};

const ObjectLayout = () => {
    const o = useRecordContext();
    const refresh = useRefresh();
    if (!o) return null;
    const hitsColumns = [
        { label: 'Hit', render: h => <HitChip hit={h} /> },
        { label: 'Fields', source: 'fields' },
        { label: 'Reviewer', source: 'reviewer' },
        { label: 'Note', render: h => <Clipped text={h.note || ''} max={160} /> },
        { label: 'Tags', render: h => <TagChips tags={h.tags} /> },
    ];
    return (
        <Box p={2}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography variant="h6">
                    {o.type} {o.name} <Typography component="span" color="text.secondary">({o.parser})</Typography>
                </Typography>
                <SourceChip source={o.source} />
            </Stack>
            <Typography variant="body2" gutterBottom>
                <Link to={o.project_id ? showUrl('projects', o.project_id) : listUrl('projects', { q: o.project_path })}>{o.project_path}</Link>
                {' · '}<Link to={listUrl('objects', { project_id: o.project_id })}>objects of the project</Link> - {o.file}{o.line ? `:${o.line}` : ''}
                {' - '}{o.source === 'orphan' ? 'no live branch has it' : `from ${o.source}`}
            </Typography>
            {o.props && Object.keys(o.props).length > 0 && (
                <Typography variant="body2" gutterBottom>
                    {Object.entries(o.props).map(([k, v]) => `${k}=${v}`).join(', ')}
                </Typography>
            )}
            {o.comment && (
                <Typography variant="body2" color="text.secondary" gutterBottom component="div">
                    <Clipped text={o.comment} max={400} />
                </Typography>
            )}
            <Box my={1}><TagChips tags={o.tags} /></Box>

            <Box mt={2} display="flex" alignItems="center" gap={2}>
                <Typography variant="subtitle1">Object hits and labels</Typography>
                <LabelActions object={o} hits={o.object_hits} onChange={refresh} />
            </Box>
            <SimpleTable rows={o.object_hits} rowKey={h => h.id} empty="No hits on the object itself" columns={hitsColumns} />

            <Typography variant="subtitle1" sx={{ mt: 3 }}>Fields ({o.fields.length})</Typography>
            <SimpleTable rows={o.fields} rowKey={f => f.name} empty="No fields" columns={[
                { label: 'Field', render: f => <b>{f.name}</b> },
                { label: 'Type', source: 'type' },
                { label: 'Comment', render: f => (f.comment ? <Clipped text={f.comment} max={120} /> : null) },
                { label: 'Samples', render: f => (f.samples || []).join(', ') },
                { label: 'Line', source: 'line' },
                { label: 'Hits', render: f => (
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" component="span">
                        {f.hits.map(h => <HitChip key={h.id} hit={h} />)}
                    </Stack>
                ) },
                { label: '', render: f => <LabelActions object={o} fieldName={f.name} hits={f.hits} onChange={refresh} /> },
            ]} />
        </Box>
    );
};

const ObjectTitle = () => {
    const o = useRecordContext();
    return <span>Object {o ? `${o.name} (${o.type})` : ''}</span>;
};

const ObjectActions = () => {
    const o = useRecordContext();
    if (!o) return null;
    return (
        <TopToolbar>
            <Button label="Hits of this object" component={Link} to={listUrl('hits', { object_key: o.id, presence: 'all' })} />
        </TopToolbar>
    );
};

export const ObjectShow = () => (
    <Show title={<ObjectTitle />} actions={<ObjectActions />}>
        <ObjectLayout />
    </Show>
);
