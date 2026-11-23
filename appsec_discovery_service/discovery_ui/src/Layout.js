import React, { useState } from 'react';
import {
    AppBar, Layout, Menu, MenuItemLink, TitlePortal, useDataProvider, useGetResourceLabel, useResourceDefinitions,
    useSidebarState,
} from 'react-admin';
import { Badge, Box, Collapse, Typography } from '@mui/material';
import ViewListIcon from '@mui/icons-material/ViewList';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import { queueCounts } from './choices';
import { useAutoRefresh, useFetch } from './common';
import { MENUS, RoleSwitcher, useRole } from './roles';
import { ScopeBar, ScopeUrlSync, useScope } from './scope';

// App bar with the scope bar ("Scope: grp/payments") and the role switcher ("View as: Admin | Datasec"): the role
// orders the menu and picks the home page; the scope narrows every list and count to a GitLab group.
const RoleAppBar = () => (
    <AppBar>
        <TitlePortal />
        <Box flex="1" />
        <ScopeBar />
        <RoleSwitcher />
    </AppBar>
);

const BADGE_REFRESH_MS = 60000;

// Menu badges: open hits of the review queues (Review: questions + pending + model unsure, the same sets as the tabs,
// one GET /hits/aggregate from the statistics snapshot) and open work for a harness model (Harness work), refreshed
// every minute (slower in a hidden tab, backing off on errors). A badge is hidden at 0 and while its request fails.
const useMenuBadges = () => {
    const dataProvider = useDataProvider();
    const { scope } = useScope();
    const hits = useFetch(() => dataProvider.hitsAggregate({ by: ['queue'], filter: { field_marks: false } })
        .then(({ data }) => ({ data: queueCounts(data.rows).open })), [scope]);
    const work = useFetch(() => dataProvider.llmWorkStats().then(({ data }) => {
        const p = (data && data.by_purpose) || {};
        return { data: ((p.verify && p.verify.open) || 0) + ((p.score && p.score.open) || 0) };
    }), []);
    useAutoRefresh(true, () => Promise.all([hits.reload(), work.reload()]).then(r => r.every(Boolean)), BADGE_REFRESH_MS);
    const count = state => (state.error || !state.data ? 0 : state.data);
    return { hits: count(hits), harness: count(work) };
};

const WithBadge = ({ count, children }) => (count
    ? <Badge badgeContent={count > 999 ? '999+' : count} color="primary" max={9999}>{children}</Badge>
    : children);

const Item = ({ item, badges }) => {
    const definitions = useResourceDefinitions();
    const getLabel = useGetResourceLabel();
    const count = item.badge ? badges[item.badge] : 0;
    if (item.resource) {
        const definition = definitions[item.resource];
        if (!definition) return null;
        const Icon = definition.icon || ViewListIcon;
        return <MenuItemLink to={`/${item.resource}`} primaryText={getLabel(item.resource, 2)}
                             leftIcon={<WithBadge count={count}><Icon /></WithBadge>} />;
    }
    const Icon = item.icon || ViewListIcon;
    return <MenuItemLink to={item.to} primaryText={item.label} leftIcon={<WithBadge count={count}><Icon /></WithBadge>} />;
};

const Section = ({ section, open, badges }) => {
    const [expanded, setExpanded] = useState(!section.collapsed);
    const Chevron = expanded ? ExpandMoreIcon : ChevronRightIcon;
    return (
        <Box>
            {open && (
                <Typography variant="overline" color="text.secondary" component="div"
                            role={section.collapsed ? 'button' : undefined} aria-expanded={section.collapsed ? expanded : undefined}
                            onClick={() => section.collapsed && setExpanded(!expanded)}
                            sx={{ px: 2, pt: 1, lineHeight: 2, cursor: section.collapsed ? 'pointer' : 'default',
                                  display: 'flex', alignItems: 'center', userSelect: 'none' }}>
                    {section.collapsed && <Chevron fontSize="small" />}{section.section}
                </Typography>
            )}
            <Collapse in={expanded || !open}>
                {section.items.map(item => <Item key={item.to || item.resource} item={item} badges={badges} />)}
            </Collapse>
        </Box>
    );
};

// Role-aware menu: the sections of roles.MENUS; the other role's pages stay reachable in a collapsed section.
const RoleMenu = () => {
    const { role } = useRole();
    const [open] = useSidebarState();
    const badges = useMenuBadges();
    return (
        <Menu>
            {MENUS[role].map(section => <Section key={section.section} section={section} open={open} badges={badges} />)}
        </Menu>
    );
};

export const RoleLayout = props => (
    <>
        <ScopeUrlSync />
        <Layout {...props} appBar={RoleAppBar} menu={RoleMenu} />
    </>
);
