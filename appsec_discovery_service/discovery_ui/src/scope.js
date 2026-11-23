import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useRefresh } from 'react-admin';
import { useLocation, useSearchParams } from 'react-router-dom';
import { Box, Typography } from '@mui/material';
import { GroupPicker } from './common';
import { setCurrentScope } from './customDataProvider';

// The GitLab group scope ("Scope: grp/payments" in the app bar): a prefix of the projects' full_path. It lives in the
// URL (`?scope=grp/payments`, so a link carries it) and is remembered per browser; the data provider adds it as
// `group=` to every hits / objects / projects list and to the aggregate, cluster and decision filters (every page
// shows the same slice of the landscape). The Review, Objects and Projects titles name it.

const STORAGE_KEY = 'ui_scope';

const readScope = () => {
    try { return localStorage.getItem(STORAGE_KEY) || ''; } catch (e) { return ''; }
};

const ScopeContext = createContext({ scope: '', setScope: () => {} });

export const ScopeProvider = ({ children }) => {
    const [scope, setScopeState] = useState(() => { const s = readScope(); setCurrentScope(s); return s; });
    const setScope = useCallback(value => {
        const s = (value || '').trim().replace(/^\/+|\/+$/g, '');
        setCurrentScope(s);
        setScopeState(s);
        try { if (s) localStorage.setItem(STORAGE_KEY, s); else localStorage.removeItem(STORAGE_KEY); } catch (e) { /* not remembered */ }
    }, []);
    const value = useMemo(() => ({ scope, setScope }), [scope, setScope]);
    return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>;
};

export const useScope = () => useContext(ScopeContext);

// Keeps `?scope=` in the URL and the state in step (inside the router): a link with another scope wins over the
// remembered one; react-admin rewrites the search of list pages with its own keys, so the scope is written back.
export const ScopeUrlSync = () => {
    const { scope, setScope } = useScope();
    const [params, setParams] = useSearchParams();
    const location = useLocation();
    const written = useRef(null);
    useEffect(() => {
        const inUrl = params.get('scope');
        if (inUrl !== null && inUrl !== scope && inUrl !== written.current) { setScope(inUrl); return; }
        if ((inUrl || '') !== (scope || '')) {
            const next = new URLSearchParams(params);
            if (scope) next.set('scope', scope); else next.delete('scope');
            written.current = scope;
            setParams(next, { replace: true });
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [scope, location.search]);
    return null;
};

// "Scope: [grp/payments x]" in the app bar; a change refreshes the lists on the page (their filters did not change,
// the data provider adds the new group).
export const ScopeBar = () => {
    const { scope, setScope } = useScope();
    const refresh = useRefresh();
    const change = value => { setScope(value); setTimeout(refresh, 0); };
    return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mr: 2, minWidth: 0 }}>
            <Typography variant="body2" component="span" sx={{ whiteSpace: 'nowrap' }}>Scope:</Typography>
            <Box sx={{
                bgcolor: 'rgba(255,255,255,0.15)', borderRadius: 1, px: 1, minWidth: 240,
                '& .MuiInputBase-root, & .MuiInputBase-input, & .MuiSvgIcon-root': { color: 'inherit' },
                '& .MuiInput-underline:before, & .MuiInput-underline:hover:not(.Mui-disabled):before': { borderBottomColor: 'rgba(255,255,255,0.5)' },
                '& .MuiFormLabel-root': { color: 'rgba(255,255,255,0.8)' },
            }}>
                <GroupPicker value={scope} onChange={change} label={scope ? 'GitLab group' : 'all groups'} variant="standard"
                             sx={{ minWidth: 240 }} />
            </Box>
        </Box>
    );
};

// "Review · grp/payments": the page title with the current scope
export const scopedTitle = (title, scope) => (scope ? `${title} · ${scope}` : title);
