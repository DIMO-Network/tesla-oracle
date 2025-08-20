import {createContext} from '@lit/context';

// AuthContext is not necessarily just Auth anymore, it's more of a session context
export interface AuthContext {
    // todo rename to JWT or AuthToken
    token: string;
    // this is an optional parameter for Mobile App to open the webview with a specific TokenId to onboard it instead of a new one.
    // if this is not set, it mints a brand new vehicle NFT. If the definition id mismatches the vin etc, backend will mint new nft as well.
    vehicleTokenId: string;
}

export enum AuthEventType {
    LOGIN = 'auth.login',
    LOGOUT = 'auth.logout',
}

export const createLoginEvent = (token: string) => {
    return new CustomEvent(AuthEventType.LOGIN, {
        bubbles: true,
        composed: true,
        detail: {
            token,
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
