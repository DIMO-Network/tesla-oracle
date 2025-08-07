import {css, html,  unsafeCSS} from 'lit'
import {Task} from '@lit/task'

// @ts-ignore
import styles from '@styles/main.css?inline'

import {customElement, property} from "lit/decorators.js";
import {consume} from "@lit/context";

import {TeslaSettingsContext, teslaSettingsContext} from "@context/tesla-settings.context.ts";
import {TeslaAuthContext, teslaAuthContext} from "@context/tesla-auth.context.ts";
import qs from "qs";
import {repeat} from "lit/directives/repeat.js";
import {BaseOnboardingElement} from "@elements/base-onboarding-element.ts";
import {MessageService} from "@services/message.service.ts";

interface DeviceDefinition {
    id: string;
    make: string;
    model: string;
    year: number;
}

interface TeslaVehicle {
    externalId: string;
    vin: string;
    definition: DeviceDefinition;
}

interface VehiclesResponse {
    vehicles: TeslaVehicle[];
}

@customElement('tesla-element')
export class TeslaElement extends BaseOnboardingElement {
    static styles = css`${unsafeCSS(styles)}`;

    @consume({context: teslaSettingsContext, subscribe: true})
    @property({attribute: false})
    private teslaSettings?: TeslaSettingsContext;

    @consume({context: teslaAuthContext, subscribe: true})
    @property({attribute: false})
    private teslaAuth?: TeslaAuthContext;

    protected messageService: MessageService = MessageService.getInstance();

    private loadVehiclesTask = new Task(this, {
        task: async ([authorizationCode, redirectUri], {}) => {
            if (!authorizationCode || !redirectUri) {
                return [];
            }

            const response = await this.api.callApi<VehiclesResponse>("POST", "/v1/tesla/vehicles", {
                authorizationCode,
                redirectUri
            }, true);
            return response.data?.vehicles || [];
        },
        args: () => [this.teslaAuth?.code, this.teslaSettings?.redirectUri]
    });

    private onboardVehicleTask = new Task(this, {
        task: async ([vin]: [string], {}) => {
            if (!vin) {
                return;
            }

            const finalized = await this.onboardVINs([vin]);

            if (!finalized || !(finalized?.vehicles.length > 0)) {
                return;
            }

            this.messageService.sendMessage({type: 'onboarded', data: finalized.vehicles})
        },
        autoRun: false
    });

    private renderVehicles(vehicles: TeslaVehicle[] | readonly[]) {
        return html`
            ${repeat(vehicles, (_, i) => i, (item) => html`
                <div class="grid-cols-12">
                    <div class="col-span-9">
                        ${item.vin}: ${item.definition.model} ${item.definition.year}
                    </div>
                    <div class="col-span-3">
                        ${this.onboardVehicleTask.render({
                            initial: () => html`<button class="button" @click=${() => this.handleOnboardClick(item.vin)}>Onboard</button>`,
                            pending: () => html`<button class="button in-progress" disabled>...</button>`,
                            complete: () => html`<button class="button done" disabled>Finished</button>`,
                            error: () => html`<button class="button" @click=${() => this.handleOnboardClick(item.vin)}>Onboard</button>`,
                        })}
                    </div>
                </div>`)}
        `
    }

    render() {
        return html`
            <div>
                <div>
                    <a href="${this.getAuthUrl()}" type="button" class="button">
                        Onboard my Tesla
                    </a>
                </div>
                <div>
                    ${this.loadVehiclesTask.render({
                        pending: () => html`
                            <div class="font-mono">Loading vehicles...</div>`,
                        complete: (vehicles) => this.renderVehicles(vehicles),
                    })}
                </div>
            </div>
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

    handleOnboardClick(vin: string) {
        this.onboardVehicleTask.run([vin]);
    }
}
