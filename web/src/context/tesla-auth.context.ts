import {createContext} from '@lit/context';

export interface TeslaAuthContext {
    code: string;
    locale: string;
    state: string;
    issuer: string;
}

export const teslaAuthContext = createContext<TeslaAuthContext>('auth');