import {createContext} from '@lit/context';

// settings from backend for tesla
export interface TeslaSettingsContext {
    clientId: string;
    authUrl: string;
    redirectUri: string;
    virtualKeyUrl: string;
}

export const teslaSettingsContext = createContext<TeslaSettingsContext>('tesla-settings');