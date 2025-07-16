import {html, LitElement, css, unsafeCSS} from 'lit'

// @ts-ignore
import styles from '@styles/main.css?inline'

import {PropertyValues} from "@lit/reactive-element";
import {customElement, property} from "lit/decorators.js";
import {consume} from "@lit/context";

import {TeslaSettingsContext, teslaSettingsContext} from "@context/tesla-settings.context.ts";
import {TeslaAuthContext, teslaAuthContext} from "@context/tesla-auth.context.ts";
import qs from "qs";

@customElement('tesla-element')
export class TeslaElement extends LitElement {
    static styles = css`${unsafeCSS(styles)}`;

    @consume({context: teslaSettingsContext, subscribe: true})
    @property({attribute: false})
    private teslaSettings?: TeslaSettingsContext;

    @consume({context: teslaAuthContext, subscribe: true})
    @property({attribute: false})
    private teslaAuth?: TeslaAuthContext;



    constructor() {
        super();
    }

    async connectedCallback() {
        super.connectedCallback();
    }

    willUpdate(p: PropertyValues) {
        console.log('Tesla WILL UPDATE', p)
        console.log(this.teslaAuth)
        console.log(this.teslaSettings)

        if (this.teslaAuth?.code && this.teslaSettings?.redirectUri) {
            //this.teslaService.getVehicles(this.teslaAuth.code, this.teslaSettings.redirectUri!);
            console.log('TESLA', this.teslaAuth, this.teslaSettings)
        }
    }

    render() {
        return html`
            <a href="${this.getAuthUrl()}" type="button" class="button">
                Onboard my Tesla
            </a>
        `;
    }

    getAuthUrl() {
        const state = this.teslaAuth?.state;
        const url = this.teslaSettings?.authUrl;
        const clientId = this.teslaSettings?.clientId;
        const redirectUri = this.teslaSettings?.redirectUri;

        const query = qs.stringify({
            prompt_missing_scopes: true,
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: [
                'openid',
                'offline_access',
                'user_data',
                'vehicle_device_data',
                'vehicle_cmds',
                'vehicle_charging_cmds',
                'vehicle_location',
            ].join(' '),
            state: state,
        });

        return `${url}?${query}`;
    }

}
