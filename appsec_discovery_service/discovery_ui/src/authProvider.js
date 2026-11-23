import { stringify } from 'query-string';

const apiUrl = '/api';

// exp (seconds) of a JWT, or 0 when it cannot be read
const tokenExpiry = (token) => {
    try {
        const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        return payload.exp || 0;
    } catch (e) {
        return 0;
    }
};

export const getToken = () => {
    const token = localStorage.getItem('token');
    if (!token) {
        return null;
    }
    if (tokenExpiry(token) * 1000 <= Date.now()) {
        localStorage.removeItem('token');
        return null;
    }
    return token;
};

const authProvider = {
    login: ({ username, password }) => {
        const request = new Request(`${apiUrl}/token`, {
            method: 'POST',
            body: stringify({ username, password }),
            headers: new Headers({ 'Content-Type': 'application/x-www-form-urlencoded' }),
        });
        return fetch(request)
            .then(response => {
                if (response.status === 429) {
                    throw new Error('Too many login attempts, wait a minute');
                }
                if (response.status < 200 || response.status >= 300) {
                    return response.json().catch(() => ({}))
                        .then(body => { throw new Error(body.detail || response.statusText || `Login failed (${response.status})`); });
                }
                return response.json();
            })
            .then(({ access_token }) => {
                localStorage.setItem('token', access_token);
            });
    },
    logout: () => {
        localStorage.removeItem('token');
        return Promise.resolve();
    },
    checkError: ({ status }) => {
        if (status === 401 || status === 403) {
            localStorage.removeItem('token');
            return Promise.reject();
        }
        return Promise.resolve();
    },
    checkAuth: () => (getToken() ? Promise.resolve() : Promise.reject()),
    getPermissions: () => Promise.resolve(),
    getIdentity: () => {
        const token = getToken();
        if (!token) {
            return Promise.reject();
        }
        try {
            const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
            return Promise.resolve({ id: payload.sub, fullName: payload.sub });
        } catch (e) {
            return Promise.reject();
        }
    },
};

export default authProvider;
