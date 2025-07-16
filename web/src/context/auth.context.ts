import {createContext} from '@lit/context';

export interface AuthContext {
    token: string;
    email: string;
}

export enum AuthEventType {
    LOGIN = 'auth.login',
    LOGOUT = 'auth.logout',
}

export const createLoginEvent = (token: string, email: string) => {
    return new CustomEvent(AuthEventType.LOGIN, {
        bubbles: true,
        composed: true,
        detail: {
            token,
            email
        }
    });
}

export const createLogoutEvent = () => {
    return new CustomEvent(AuthEventType.LOGOUT, {
        bubbles: true,
        composed: true,
    });
}

export const authContext = createContext<AuthContext>('auth');