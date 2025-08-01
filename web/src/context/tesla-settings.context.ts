import {createContext} from '@lit/context';

export interface TeslaSettingsContext {
    clientId: string;
    authUrl: string;
    redirectUri: string;
}

export const teslaSettingsContext = createContext<TeslaSettingsContext>('tesla-settings');