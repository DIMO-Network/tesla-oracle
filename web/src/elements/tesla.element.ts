import {css, html,  unsafeCSS} from 'lit'
import {Task} from '@lit/task'

// @ts-ignore
import styles from '@styles/main.css?inline'

import {customElement, property, state} from "lit/decorators.js";
import {consume} from "@lit/context";

import {TeslaSettingsContext, teslaSettingsContext} from "@context/tesla-settings.context.ts";
import {TeslaAuthContext, teslaAuthContext} from "@context/tesla-auth.context.ts";
import qs from "qs";
import {repeat} from "lit/directives/repeat.js";
import {BaseOnboardingElement} from "@elements/base-onboarding-element.ts";
import {MessageService} from "@services/message.service.ts";
import {AuthContext, authContext} from "@context/auth.context.ts";
import {LinkingService} from "@services/linking.service.ts";

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

interface VirtualKeyResponse {
    added: boolean;
    status: string;
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

    @consume({context: authContext, subscribe: true})
    @property({attribute: false})
    private auth?: AuthContext;

    // linking service wraps opening urls
    protected linkingService: LinkingService = LinkingService.getInstance();
    // wraps all the logic for sending and receiving messages from the host mobile app
    protected messageService: MessageService = MessageService.getInstance();

    @state()
    private virtualKeyChecked = false;

    @state()
    private canSetupVirtualKey = false;

    @state()
    private linkOpened = false;

    connectedCallback() {
        super.connectedCallback();

        this.linkingService.useMessageService(this.messageService);
    }

    private loadVehiclesTask = new Task(this, {
        // async lit task feature. Useful for rendering b/c handles state, in progress, error, success
        task: async ([authorizationCode, redirectUri], {}) => {
            if (!authorizationCode || !redirectUri) {
                return [];
            }

            const response = await this.api.callApi<VehiclesResponse>("POST", "/v1/tesla/vehicles", {
                authorizationCode,
                redirectUri,
            }, true);
            return response.data?.vehicles || [];
        },
        // arguments to pass into the task. This task watches the arguments for changes to execute the task
        args: () => [this.teslaAuth?.code, this.teslaSettings?.redirectUri]
    });

    private checkVirtualKeyTask = new Task(this, {
        task: async ([vin], {}) => {
            if (!vin) {
                return [];
            }
            const query = qs.stringify({vin});
            const response = await this.api.callApi<VirtualKeyResponse>("GET", `/v1/tesla/virtual-key?${query}`, null, true);
            return response.data || null;
        },
        autoRun: false
    });

    private onboardVehicleTask = new Task(this, {
        task: async ([vin, vehicleTokenId]: [string, number?], {}) => {
            if (!vin) {
                return;
            }

            const finalized = await this.onboardVINs([{vin, vehicleTokenId}]);

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
                <div class="mb-6">
                    <div class="text-white mb-4">
                        <div class="text-sm text-gray-400 mb-1">VIN: ${item.vin}</div>
                        <div class="text-lg font-medium">${item.definition.model} ${item.definition.year}</div>
                    </div>
                    <div class="space-y-3">
                        <button
                                class="button-primary ${this.virtualKeyChecked ? 'disabled' : ''}"
                                @click=${() => this.handleOnboardClick(item.vin)}
                                ?disabled=${this.virtualKeyChecked}
                        >Start onboarding</button>

                        <div class="text-gray-400 text-sm">
                            ${this.checkVirtualKeyTask.render({
                                initial: () => html``,
                                pending: () => html`<span>Checking virtual key status...</span>`,
                                complete: () => html`<span>Virtual key status: ${(this.checkVirtualKeyTask.value as VirtualKeyResponse).status}</span>`,
                                error: () => html`<span>Failed to check virtual key status</span>`,
                            })}
                        </div>

                        <button
                                class="button-primary ${!this.canSetupVirtualKey ? 'disabled' : ''}"
                                @click=${() => this.handleVirtualKeyClick(item.vin)}
                                ?hidden=${!this.virtualKeyChecked || !this.canSetupVirtualKey}
                        >Setup Virtual Key</button>

                        <button
                                class="button-primary"
                                @click=${() => this.handleOnboardClick(item.vin)}
                                ?disabled=${this.virtualKeyChecked}
                                ?hidden=${!this.linkOpened}
                        >Verify virtual key setup</button>

                        <button
                                class="button-primary ${!this.virtualKeyChecked || this.canSetupVirtualKey ? 'disabled' : ''}"
                                @click=${() => this.handleContinueClick(item.vin)}
                                ?disabled=${!this.virtualKeyChecked || this.canSetupVirtualKey}
                                ?hidden=${!this.virtualKeyChecked}
                        >Continue</button>
                    </div>
                </div>`)}
        `
    }

    render() {
        return html`
            <div>
                <div class="mb-8">
                    <a href="${this.getAuthUrl()}" class="button-primary">
                        Connect Tesla Account
                    </a>
                </div>
                <div>
                    ${this.loadVehiclesTask.render({
                        pending: () => html`
                            <div class="text-gray-400 text-center py-4">Loading vehicles...</div>`,
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

    async handleOnboardClick(vin: string) {
        await this.checkVirtualKeyTask.run([vin])
        const value = this.checkVirtualKeyTask.value as VirtualKeyResponse;
        if (!!value && !!value.status) {
            this.canSetupVirtualKey = value.status === "Unpaired";
        } else {
            this.canSetupVirtualKey = false;
        }

        this.virtualKeyChecked = true;
    }

    async handleVirtualKeyClick(_: string) {
        if (!this.teslaSettings?.virtualKeyUrl) {
            return;
        }
        // this blocks until the host completes the operation (uses a promise that waits for opened link to have a specific url). Has a timeout.
        const openedUrl = await this.linkingService.openLink(this.teslaSettings.virtualKeyUrl);
        // this should be true, but just in case. there could be timeouts
        if (openedUrl.url === this.teslaSettings.virtualKeyUrl) {
            this.linkOpened = true;
        }
    }

    async handleContinueClick(vin: string) {
        let vehicleTokenId = undefined
        if (this.auth?.vehicleTokenId) {
            // just making sure it is a number
            const tid = Number(this.auth.vehicleTokenId)
            if (!Number.isNaN(tid)) {
                vehicleTokenId = tid
            }
        }

        this.onboardVehicleTask.run([vin, vehicleTokenId]);
    }
}
