const query = gql`
	query OkfsCodesQuery {
		okfsCodes {
			code
			name
		}
	}
`;

export const mutation = gql`
	mutation ContractorCreateMutation($input: CreateContractorInput!) {
		contractor {
			create(input: $input) {
				id
			}
		}
	}
`;

const getOzonId = gql<UserCheckQueryVariables, UserCheckQuery>`
	query UserCheck {
		user {
			id
			email
		}
	}
`.pipe((data) => data.User).execute;

const getBankId = gql<BankUserQueryVariables, BankUserQuery>`
	query BankUser {
		me {
			id
		}
	}
`.pipe((data) => data.me.id).execute;