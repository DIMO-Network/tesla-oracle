import {LitElement, html} from 'lit';
import {provide} from '@lit/context';

import {customElement, property} from "lit/decorators.js";
import {ApiService} from "@services/api-service.ts";
import {TeslaSettingsContext, teslaSettingsContext} from "@context/tesla-settings.context.ts";

@customElement('tesla-settings-provider')
export class SettingsProvider extends LitElement {

    @provide({context: teslaSettingsContext})
    @property({attribute: false})
    private _settings: TeslaSettingsContext = {
        clientId: '',
        authUrl: '',
        redirectUri: '',
    };

    private api = ApiService.getInstance();

    async connectedCallback() {
        super.connectedCallback();

        const settings = await this.api.callApi<TeslaSettingsContext>('GET', '/v1/tesla/settings', null, true);
        console.log('SETTINGS', settings)
        this._settings = {
            ...this._settings,
            ...settings.data
        };
    }

    render() {
        return html`<slot></slot>`;
    }
}
