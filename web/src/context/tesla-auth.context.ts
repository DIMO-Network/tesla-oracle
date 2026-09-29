import {createContext} from '@lit/context';

// these are the values that we get from tesla when we complete the authorization with tesla, and then it redirects back to our web app.
// one thing that is not implemented here, is the state value is randomly generated once, and then it is passed to the tesla auth flow for start onboarding.
// after the onboarding is successful and they redirect back to us, the state SHOULD MATCH what was originally provided to us.
// todo Would be good idea to check the state (store it first, compare after).
export interface TeslaAuthContext {
    code: string;
    locale: string;
    state: string;
    issuer: string;
}

// Its own key: sharing 'auth' with authContext made consumers of authContext get
// this context from the nearer tesla-auth-provider instead.
export const teslaAuthContext = createContext<TeslaAuthContext>('tesla-auth');