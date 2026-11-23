import React from 'react';
import { ArrayInput, SimpleFormIterator, TextInput, FunctionField } from 'react-admin';

// Tags a rule (or a manual label) sets on the object of every hit that matches (status match).
export const TagsInput = ({ label = 'Tags set on matching objects' }) => (
    <ArrayInput source="tags" label={label}>
        <SimpleFormIterator inline disableReordering>
            <TextInput source="" label="Tag (e.g. personal-data)" helperText={false} />
        </SimpleFormIterator>
    </ArrayInput>
);

export const TagsField = ({ label = 'Tags' }) => (
    <FunctionField label={label} render={r => (r && r.tags && r.tags.length ? r.tags.join(', ') : '')} />
);
