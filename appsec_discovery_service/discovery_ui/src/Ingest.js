import React from 'react';
import {
    List, Datagrid, TextField, NumberField, BooleanField, FunctionField, AutocompleteInput, ListContextProvider,
    Pagination, ReferenceInput, TextInput, useListContext, useRecordContext,
} from 'react-admin';
import { Box, Chip, Typography } from '@mui/material';
import { Ago, Clipped, SimpleTable } from './common';

// Ingest batches (sec. 7.9): the states pushed by external collectors (POST /ingest). The API answers a plain
// array (<= 500, newest first): paging and the created_by filter are done here.

const PAGE = 50;
const STALE_MS = 7 * 24 * 3600 * 1000;

const filters = [
    <ReferenceInput source="project_id" reference="projects" alwaysOn>
        <AutocompleteInput optionText="full_path" filterToQuery={q => ({ q })} label="Project" />
    </ReferenceInput>,
    <TextInput source="created_by" label="Collector (token)" />,
];

const BatchDetails = () => {
    const b = useRecordContext();
    if (!b) return null;
    const stats = b.stats ? Object.entries(b.stats).map(([key, value]) => ({ key, value })) : [];
    return (
        <Box p={1}>
            {b.error && <Typography color="error" variant="body2" gutterBottom>{b.error}</Typography>}
            <SimpleTable rows={stats} rowKey={r => r.key} empty="No stats (not processed yet)" columns={[
                { label: 'Stat', source: 'key' },
                { label: 'Value', render: r => (typeof r.value === 'object' ? JSON.stringify(r.value) : String(r.value)) },
            ]} />
        </Box>
    );
};

// one row per collector (created_by): its latest batch
const Collectors = ({ rows }) => {
    const byCollector = {};
    rows.forEach(b => {
        const key = b.created_by || '-';
        if (!byCollector[key] || (b.created_at || '') > (byCollector[key].created_at || '')) byCollector[key] = b;
    });
    const collectors = Object.values(byCollector).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    return (
        <Box px={2} pb={1}>
            <Typography variant="subtitle2" gutterBottom>Collectors</Typography>
            <SimpleTable rows={collectors} rowKey={r => r.created_by || '-'} empty="No batch pushed yet" columns={[
                { label: 'Collector', render: r => r.created_by || '-' },
                { label: 'Last batch', render: r => (
                    <>
                        <Ago value={r.created_at} />
                        {r.created_at && Date.now() - new Date(r.created_at).getTime() > STALE_MS
                            && <Chip size="small" color="warning" label="stale" sx={{ ml: 1 }} title="no batch in 7 days" />}
                    </>
                ) },
                { label: 'Project', source: 'project' },
                { label: 'Status', source: 'status' },
                { label: 'Objects', source: 'objects' },
                { label: 'Error', render: r => (r.error ? <Clipped text={r.error} max={80} /> : '') },
            ]} />
        </Box>
    );
};

// the API returns everything at once: filter by collector and page here
const ClientPaged = ({ children }) => {
    const ctx = useListContext();
    const { data = [], filterValues = {}, page, perPage } = ctx;
    const filtered = filterValues.created_by ? data.filter(b => (b.created_by || '').includes(filterValues.created_by)) : data;
    const slice = filtered.slice((page - 1) * perPage, page * perPage);
    return (
        <>
            <Collectors rows={data} />
            <ListContextProvider value={{ ...ctx, data: slice, total: filtered.length }}>
                {children}
            </ListContextProvider>
        </>
    );
};

export const IngestList = () => (
    <List filters={filters} title="Ingest batches" perPage={PAGE} pagination={false}>
        <ClientPaged>
            <Datagrid bulkActionButtons={false} expand={<BatchDetails />}>
                <TextField source="id" sortable={false} />
                <TextField source="project" sortable={false} />
                <TextField source="parser" sortable={false} />
                <TextField source="snapshot" sortable={false} emptyText="-" />
                <FunctionField label="Status" render={r => <Chip size="small" variant="outlined" label={r.status} color={r.error ? 'error' : 'default'} />} />
                <NumberField source="objects" sortable={false} />
                <NumberField source="fields" sortable={false} />
                <BooleanField source="llm" label="LLM" sortable={false} />
                <TextField source="created_by" label="Collector" sortable={false} />
                <FunctionField label="Pushed" render={r => <Ago value={r.created_at} />} />
                <FunctionField label="Processed" render={r => (r.processed_at ? <Ago value={r.processed_at} /> : '-')} />
                <FunctionField label="Error" render={r => (r.error ? <Clipped text={r.error} max={80} /> : '')} />
            </Datagrid>
            <Pagination rowsPerPageOptions={[PAGE]} />
        </ClientPaged>
    </List>
);
