import gql from 'graphql-tag';
import { queryFactory } from './helpers/queryFactory';
import type { Failable } from '$types/service/failablePromise';
import type {
	ProfileLoginQuery as Query,
	ProfileLoginQueryVariables as Variables,
} from './__queryTypes/ProfileLogin';

type Result = { login: string };

export const query = gql`
	query ProfileLoginQuery {
		me {
			login
		}
	}
`;

function mapper(data: Query): Failable<Result> {
	return [data.me, null];
}

export const profileLogin = queryFactory<Query, Variables, Result>(query, mapper);

export type { Result as ProfileLoginQueryResult };

