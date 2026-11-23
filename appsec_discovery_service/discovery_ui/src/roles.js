import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { ToggleButton, ToggleButtonGroup, Tooltip, Typography } from '@mui/material';
import SpeedIcon from '@mui/icons-material/Speed';
import WorkIcon from '@mui/icons-material/Work';
import FolderIcon from '@mui/icons-material/Folder';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import MemoryIcon from '@mui/icons-material/Memory';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import DashboardIcon from '@mui/icons-material/Dashboard';
import FactCheckIcon from '@mui/icons-material/FactCheck';
import PsychologyIcon from '@mui/icons-material/Psychology';
import SpellcheckIcon from '@mui/icons-material/Spellcheck';
import TableChartIcon from '@mui/icons-material/TableChart';
import MapIcon from '@mui/icons-material/Map';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

// Two ways of using the same single-user UI (no auth change): the service ADMIN keeps the pipeline (scans, LLM
// runs, harness work) going; the DATASEC (data security) role writes rules, reviews hits and improves prompts. The role
// orders the menu and picks the home page; it is remembered per browser (localStorage) and can be switched in the
// app bar at any time. Every page stays reachable in both roles.
export const ROLES = {
    admin: { id: 'admin', label: 'Admin', home: 'Pipeline health' },
    datasec: { id: 'datasec', label: 'Datasec', home: 'Work desk' },
};

const STORAGE_KEY = 'ui_role';
// role ids stored by earlier versions: 'engineer' is now 'datasec' (the stored value is rewritten once)
const OLD_ROLES = { engineer: 'datasec' };

const readRole = () => {
    try {
        let value = localStorage.getItem(STORAGE_KEY);
        if (OLD_ROLES[value]) {
            value = OLD_ROLES[value];
            try { localStorage.setItem(STORAGE_KEY, value); } catch (e) { /* not remembered */ }
        }
        return ROLES[value] ? value : 'datasec';
    } catch (e) {
        return 'datasec';
    }
};

const RoleContext = createContext({ role: 'datasec', setRole: () => {} });

export const RoleProvider = ({ children }) => {
    const [role, setRoleState] = useState(readRole);
    const setRole = useCallback(value => {
        if (!ROLES[value]) return;
        setRoleState(value);
        try { localStorage.setItem(STORAGE_KEY, value); } catch (e) { /* private window: not remembered */ }
    }, []);
    const value = useMemo(() => ({ role, setRole }), [role, setRole]);
    return <RoleContext.Provider value={value}>{children}</RoleContext.Provider>;
};

export const useRole = () => useContext(RoleContext);

const ROLE_TIP = 'Changes the home page and the menu order; every page stays reachable';

// "View as: [Admin | Datasec]" in the app bar
export const RoleSwitcher = () => {
    const { role, setRole } = useRole();
    return (
        <Tooltip title={ROLE_TIP}>
            <Typography component="div" variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 1, mr: 2 }}>
                <span>View as:</span>
                <ToggleButtonGroup size="small" exclusive value={role} aria-label="View as"
                                   onChange={(e, value) => value && setRole(value)}
                                   sx={{ '& .MuiToggleButton-root': {
                                       color: 'inherit', py: 0.25, px: 1.25, textTransform: 'none',
                                       borderColor: 'rgba(255,255,255,0.5)',
                                       '&.Mui-selected': { color: 'inherit', bgcolor: 'rgba(255,255,255,0.25)' },
                                       '&.Mui-selected:hover': { bgcolor: 'rgba(255,255,255,0.3)' },
                                   } }}>
                    {Object.values(ROLES).map(r => <ToggleButton key={r.id} value={r.id}>{r.label}</ToggleButton>)}
                </ToggleButtonGroup>
            </Typography>
        </Tooltip>
    );
};

// One icon per page: resources take theirs from the <Resource icon> in App.js (this map), custom pages from the
// `icon` of their menu entry.
export const RESOURCE_ICONS = {
    hits: FactCheckIcon,
    objects: TableChartIcon,
    keyword_rules: SpellcheckIcon,
    llm_rules: PsychologyIcon,
    projects: FolderIcon,
    jobs: WorkIcon,
    ingest: CloudUploadIcon,
    tokens: VpnKeyIcon,
};

// custom pages (CustomRoutes in App.js)
const PIPELINE = { label: 'Pipeline health', icon: SpeedIcon };
const WORKDESK = { label: 'Work desk', icon: DashboardIcon };
const HARNESS = { to: '/harness', label: 'Harness work', icon: MemoryIcon, badge: 'harness' };
const LANDSCAPE = { to: '/landscape', label: 'Landscape', icon: MapIcon };
// GitLab groups: the projects of a group with their open hits, parse and LLM states (the scope bar picks one)
const GROUPS = { to: '/groups', label: 'Groups', icon: AccountTreeIcon };
// badges: 'hits' = open hits (Review), 'harness' = open checks and score items for a harness model (Layout.js)
const REVIEW = { resource: 'hits', badge: 'hits' };

// Menu of each role: sections in the order the role needs them, named by content (never by role). `to` entries are
// custom pages, `resource` entries are react-admin resources (their list page). The other role's pages sit in one
// collapsed section at the end.
export const MENUS = {
    admin: [
        { section: 'Pipeline', items: [
            { to: '/', ...PIPELINE },
            { resource: 'jobs' },
            GROUPS,
            { resource: 'projects' },
            { resource: 'ingest' },
            HARNESS,
        ] },
        { section: 'Settings', items: [
            { resource: 'tokens' },
        ] },
        { section: 'Review & rules', collapsed: true, items: [
            { to: '/workdesk', ...WORKDESK },
            REVIEW,
            { resource: 'llm_rules' },
            { resource: 'keyword_rules' },
            { resource: 'objects' },
            LANDSCAPE,
        ] },
    ],
    datasec: [
        { section: 'Work', items: [
            { to: '/', ...WORKDESK },
            REVIEW,
        ] },
        { section: 'Rules', items: [
            { resource: 'llm_rules' },
            { resource: 'keyword_rules' },
        ] },
        { section: 'Landscape', items: [
            LANDSCAPE,
            { resource: 'objects' },
            GROUPS,
            { resource: 'projects' },
        ] },
        { section: 'Harness', items: [
            HARNESS,
        ] },
        { section: 'Pipeline & settings', collapsed: true, items: [
            { to: '/pipeline', ...PIPELINE },
            { resource: 'jobs' },
            { resource: 'ingest' },
            { resource: 'tokens' },
        ] },
    ],
};
