import React from 'react';
import { Admin, CustomRoutes, Resource } from 'react-admin';
import { Route } from 'react-router-dom';
import customDataProvider from './customDataProvider';
import authProvider from './authProvider';
import { PipelineHealth } from './PipelineHealth';
import { WorkDesk } from './WorkDesk';
import { HarnessWork } from './Harness';
import { Landscape } from './Landscape';
import { KeywordRuleList, KeywordRuleEdit, KeywordRuleCreate } from './KeywordRules';
import { LlmRuleList, LlmRuleEdit, LlmRuleCreate } from './LlmRules';
import { HitList, HitShow } from './Hits';
import { ObjectList, ObjectShow } from './Objects';
import { GroupView, ProjectList, ProjectShow } from './Projects';
import { JobList, JobShow } from './Jobs';
import { IngestList } from './Ingest';
import { TokenList, TokenCreate } from './Tokens';
import { RoleLayout } from './Layout';
import { RESOURCE_ICONS, RoleProvider, useRole } from './roles';
import { ScopeProvider } from './scope';

// The home page depends on the role chosen in the app bar: the admin sees the pipeline health, the datasec the
// work desk (roles.js). Both pages stay reachable at /pipeline and /workdesk.
const Home = () => {
    const { role } = useRole();
    return role === 'admin' ? <PipelineHealth /> : <WorkDesk />;
};

// options.label is the menu entry and the page title of each resource (one word list: roles.js / choices.js)
const App = () => (
    <RoleProvider>
        <ScopeProvider>
            <Admin title="AppSec Discovery" dashboard={Home} layout={RoleLayout} dataProvider={customDataProvider}
                   authProvider={authProvider} requireAuth>
                <CustomRoutes>
                    <Route path="/pipeline" element={<PipelineHealth />} />
                    <Route path="/workdesk" element={<WorkDesk />} />
                    <Route path="/harness" element={<HarnessWork />} />
                    <Route path="/landscape" element={<Landscape />} />
                    <Route path="/groups" element={<GroupView />} />
                </CustomRoutes>
                <Resource name="hits" options={{ label: 'Review' }} icon={RESOURCE_ICONS.hits} list={HitList} show={HitShow} />
                <Resource name="objects" options={{ label: 'Objects' }} icon={RESOURCE_ICONS.objects} list={ObjectList}
                          show={ObjectShow} recordRepresentation="name" />
                <Resource name="keyword_rules" options={{ label: 'Keyword rules' }} icon={RESOURCE_ICONS.keyword_rules}
                          list={KeywordRuleList} edit={KeywordRuleEdit} create={KeywordRuleCreate} />
                <Resource name="llm_rules" options={{ label: 'LLM rules' }} icon={RESOURCE_ICONS.llm_rules}
                          list={LlmRuleList} edit={LlmRuleEdit} create={LlmRuleCreate} />
                <Resource name="projects" options={{ label: 'Projects' }} icon={RESOURCE_ICONS.projects} list={ProjectList}
                          show={ProjectShow} recordRepresentation="full_path" />
                <Resource name="jobs" options={{ label: 'Jobs' }} icon={RESOURCE_ICONS.jobs} list={JobList} show={JobShow} />
                <Resource name="ingest" options={{ label: 'Ingest batches' }} icon={RESOURCE_ICONS.ingest} list={IngestList} />
                <Resource name="tokens" options={{ label: 'Service tokens' }} icon={RESOURCE_ICONS.tokens} list={TokenList}
                          create={TokenCreate} />
            </Admin>
        </ScopeProvider>
    </RoleProvider>
);

export default App;
