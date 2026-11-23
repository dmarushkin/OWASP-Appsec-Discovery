import React, { useState } from 'react';
import {
    List, Datagrid, TextField, FunctionField, Create, SimpleForm, TextInput, ArrayInput, SimpleFormIterator,
    CheckboxGroupInput, FormDataConsumer, TopToolbar, CreateButton, Button, Confirm, Link, required, useRecordContext,
    useDataProvider, useNotify, useRefresh, useRedirect,
} from 'react-admin';
import {
    Box, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField as MuiTextField, Tooltip, Typography,
} from '@mui/material';
import { Ago, listUrl } from './common';

// Service tokens (admin only): `ingest` tokens let collectors push external parser states under their project
// prefixes; `mcp` tokens give a harness / agent client its own identity (`token:<name>` as the reviewer and lease owner,
// its own rate limit) instead of sharing the admin's login token.

const SCOPES = [
    { id: 'ingest', name: 'ingest: push external parser states (POST /ingest) under the project prefixes' },
    { id: 'mcp', name: 'mcp: an MCP / REST client of its own (a harness, an agent) acting as token:<name>' },
];

// DELETE /tokens/{id}: the row stays with revoked_at set
const RevokeButton = () => {
    const record = useRecordContext();
    const dataProvider = useDataProvider();
    const notify = useNotify();
    const refresh = useRefresh();
    const [open, setOpen] = useState(false);
    const [busy, setBusy] = useState(false);
    if (!record || record.revoked_at) return null;
    const revoke = () => {
        setBusy(true);
        dataProvider.revokeToken({ id: record.id })
            .then(() => { notify(`Token "${record.name}" revoked`, { type: 'info' }); refresh(); })
            .catch(e => notify(e.message || 'Revoke failed', { type: 'warning' }))
            .finally(() => { setBusy(false); setOpen(false); });
    };
    return (
        <>
            <Button label="Revoke" onClick={() => setOpen(true)} />
            <Confirm isOpen={open} loading={busy} title={`Revoke token "${record.name}"?`}
                     content="Clients using it get 401 from then on. This cannot be undone."
                     onConfirm={revoke} onClose={() => setOpen(false)} />
        </>
    );
};

const ListActions = () => (
    <TopToolbar>
        <CreateButton label="New token" />
    </TopToolbar>
);

// the batches this token pushed (Ingest batches filtered by collector = the token's name), or the decisions of an MCP client
const LastUse = () => {
    const record = useRecordContext();
    if (!record) return null;
    if (!record.last_used_at) return <span>never</span>;
    const scopes = record.scopes || [];
    const to = scopes.includes('ingest') ? listUrl('ingest', { created_by: `token:${record.name}` })
        : listUrl('hits', { reviewer: `token:${record.name}`, presence: 'all', view: 'list' });
    return <Link to={to}><Ago value={record.last_used_at} /></Link>;
};

const ScopeChips = ({ scopes }) => (
    <Stack direction="row" spacing={0.5} component="span">
        {(scopes || []).map(s => <Chip key={s} size="small" variant="outlined" label={s} />)}
    </Stack>
);

// GET /tokens: a plain array (no paging, no sort)
export const TokenList = () => (
    <List title="Service tokens" actions={<ListActions />} pagination={false} perPage={200}>
        <Datagrid bulkActionButtons={false}>
            <TextField source="name" sortable={false} />
            <FunctionField label="Scopes" render={r => <ScopeChips scopes={r.scopes} />} />
            <FunctionField label="Project prefixes" render={r => (r.project_prefixes || []).join(', ') || '-'} />
            <TextField source="created_by" sortable={false} />
            <FunctionField label="Created" render={r => <Ago value={r.created_at} />} />
            <LastUse label="Last used" />
            <FunctionField label="Revoked" render={r => (r.revoked_at ? <Ago value={r.revoked_at} /> : '-')} />
            <RevokeButton />
        </Datagrid>
    </List>
);

// the MCP connection of a harness with its own token (the same snippet as Harness work ▸ How to connect)
export const mcpConnectSnippet = (token = '<token>') =>
    `claude mcp add --transport http appsec-discovery ${window.location.origin}/api/mcp --header "Authorization: Bearer ${token}"`;

// The token is in the create response only: show it once (with the connect snippet for mcp tokens), then go to the list.
const TokenDialog = ({ token, onClose }) => {
    const notify = useNotify();
    const copy = text => () => navigator.clipboard.writeText(text)
        .then(() => notify('Copied', { type: 'info' }))
        .catch(() => notify('Copy failed: select the text and copy it by hand', { type: 'warning' }));
    const mcp = (token.scopes || []).includes('mcp');
    return (
        <Dialog open onClose={onClose} fullWidth maxWidth="md" aria-labelledby="token-title">
            <DialogTitle id="token-title">Token "{token.name}" created</DialogTitle>
            <DialogContent>
                <Typography variant="body2" gutterBottom>Store it now: it is not shown again (only its hash is kept).</Typography>
                <MuiTextField value={token.token} fullWidth margin="dense" InputProps={{ readOnly: true }}
                              inputProps={{ 'aria-label': 'Service token', style: { fontFamily: 'monospace' } }} />
                <Typography variant="body2" color="text.secondary">
                    Scope {(token.scopes || []).join(', ')}{(token.project_prefixes || []).length ? ` on ${token.project_prefixes.join(', ')}` : ''}
                    {mcp ? ` · acts as token:${token.name} on REST and MCP (its decisions and leases carry that name)` : ''}
                </Typography>
                {mcp && (
                    <Box mt={2}>
                        <Typography variant="subtitle2">Connect a harness with it</Typography>
                        <Box component="pre" sx={{ whiteSpace: 'pre-wrap', fontSize: 12, m: 0, p: 1, bgcolor: 'action.hover', borderRadius: 1 }}>
                            {mcpConnectSnippet(token.token)}
                        </Box>
                        <Button label="Copy the connect command" size="small" onClick={copy(mcpConnectSnippet(token.token))} />
                    </Box>
                )}
            </DialogContent>
            <DialogActions>
                <Button label="Copy token" onClick={copy(token.token)} />
                <Button label="Done" onClick={onClose} />
            </DialogActions>
        </Dialog>
    );
};

const validateScopes = value => (value && value.length ? undefined : 'Pick at least one scope');

export const TokenCreate = () => {
    const redirect = useRedirect();
    const [token, setToken] = useState(null);
    return (
        <>
            <Create redirect={false} mutationOptions={{ onSuccess: data => setToken(data) }} title="New service token">
                <SimpleForm defaultValues={{ scopes: ['mcp'], project_prefixes: [] }}>
                    <Tooltip title="Admin only: POST /tokens. Ingest tokens push with POST /ingest; mcp tokens connect to /api/mcp and the REST API">
                        <Typography variant="body2">
                            A service token for a collector (scope ingest: states of an external parser, only to projects under
                            its prefixes, paths below external/) or for a harness / agent (scope mcp: its own identity,
                            its own rate limit, revocable on its own).
                        </Typography>
                    </Tooltip>
                    <TextInput source="name" validate={required()} fullWidth helperText="e.g. payments-mssql-collector or harness-claude-a" />
                    <CheckboxGroupInput source="scopes" label="Scopes" choices={SCOPES} validate={validateScopes} row={false} />
                    <FormDataConsumer>
                        {({ formData }) => {
                            const ingest = (formData.scopes || []).includes('ingest');
                            return (
                                <ArrayInput source="project_prefixes" label={ingest ? 'Project prefixes (required for ingest)' : 'Project prefixes (optional)'}
                                            validate={ingest ? required() : undefined} fullWidth>
                                    <SimpleFormIterator inline disableReordering>
                                        <TextInput source="" label="Prefix (e.g. external/payments)" helperText={false} fullWidth validate={ingest ? required() : undefined} />
                                    </SimpleFormIterator>
                                </ArrayInput>
                            );
                        }}
                    </FormDataConsumer>
                </SimpleForm>
            </Create>
            {token && <TokenDialog token={token} onClose={() => { setToken(null); redirect('list', 'tokens'); }} />}
        </>
    );
};
