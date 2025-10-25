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

interface ActiveVehicle {
    vin: string;
    vehicleTokenId: number;
    sdTokenId: number;
    subscriptionStatus: string;
}

interface DisconnectedVehicle {
    vin: string;
    vehicleTokenId: number;
    subscriptionStatus: string;
}

interface VehicleStatusesResponse {
    active: ActiveVehicle[];
    disconnected: DisconnectedVehicle[];
    new: string[];
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

    private loadVehicleStatusesTask = new Task(this, {
        task: async ([vehicles], {}) => {
            if (!vehicles || vehicles.length === 0) {
                return {active: [], disconnected: [], new: []};
            }

            // Extract VINs from Tesla vehicles
            const vins = vehicles.map((v: TeslaVehicle) => v.vin);

            // Call status endpoint with VINs
            const response = await this.api.callApi<VehicleStatusesResponse>("POST", "/v1/tesla/disconnected", {
                vins
            }, true);

            return response.data || {active: [], disconnected: [], new: []};
        },
        args: () => [this.loadVehiclesTask.value]
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

    private renderConnectPrompt() {
        return html`
            <div>
                <h1 class="text-4xl font-bold mb-4 leading-tight text-white">Let's get your Tesla connected</h1>
                <p class="text-gray-400 text-base mb-8">Connect your Tesla from the app, no DIMO device required.</p>
                <div class="mb-8">
                    <a href="${this.getAuthUrl()}" class="button-primary">
                        Connect Tesla Account
                    </a>
                </div>
            </div>
        `;
    }

    private renderActiveVehicles(vehicles: ActiveVehicle[] | readonly[]) {
        if (!vehicles || vehicles.length === 0) {
            return html``;
        }

        return html`
            <div class="mb-8">
                <h2 class="text-2xl font-bold mb-4 text-white">Your Connected Vehicles</h2>
                ${repeat(vehicles, (v) => v.vin, (vehicle) => html`
                    <div class="mb-6 p-4 border border-green-700 rounded-lg bg-green-900 bg-opacity-10">
                        <div class="text-white mb-2">
                            <div class="text-sm text-gray-400 mb-1">VIN: ${vehicle.vin}</div>
                            <div class="text-lg font-medium">Tesla Vehicle</div>
                        </div>
                        <div class="text-green-400 text-sm">✓ Already onboarded</div>
                    </div>
                `)}
            </div>
        `;
    }

    private renderDisconnectedVehicles(vehicles: DisconnectedVehicle[] | readonly[]) {
        if (!vehicles || vehicles.length === 0) {
            return html``;
        }

        return html`
            <div class="mb-8">
                <h2 class="text-2xl font-bold mb-4 text-white">Reconnect Your Tesla</h2>
                ${repeat(vehicles, (v) => v.vin, (vehicle) => html`
                    <div class="mb-6 p-4 border border-gray-700 rounded-lg">
                        <div class="text-white mb-4">
                            <div class="text-sm text-gray-400 mb-1">VIN: ${vehicle.vin}</div>
                            <div class="text-lg font-medium">Tesla Vehicle</div>
                        </div>
                        <button
                            class="button-primary"
                            @click=${() => this.handleReconnectClick(vehicle.vin, vehicle.vehicleTokenId)}
                        >Reconnect Vehicle</button>
                    </div>
                `)}
            </div>
        `;
    }

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
                ${this.loadVehiclesTask.render({
                    initial: () => this.renderConnectPrompt(),
                    pending: () => html`
                        <div class="text-gray-400 text-center py-4">Loading vehicles...</div>
                    `,
                    complete: (vehicles) => {
                        if (!vehicles || vehicles.length === 0) {
                            return this.renderConnectPrompt();
                        }

                        // Get vehicle statuses
                        const statuses = this.loadVehicleStatusesTask.value;
                        if (!statuses) {
                            return html``;
                        }

                        // Render active vehicles
                        const activeSection = this.renderActiveVehicles(statuses.active);

                        // Render disconnected vehicles
                        const disconnectedSection = this.renderDisconnectedVehicles(statuses.disconnected);

                        // Filter vehicles to only show new ones (not in active or disconnected)
                        const activeVINs = new Set(statuses.active.map((v: ActiveVehicle) => v.vin));
                        const disconnectedVINs = new Set(statuses.disconnected.map((v: DisconnectedVehicle) => v.vin));
                        const newVehicles = vehicles.filter((v: TeslaVehicle) =>
                            !activeVINs.has(v.vin) && !disconnectedVINs.has(v.vin)
                        );

                        return html`
                            ${activeSection}
                            ${disconnectedSection}
                            ${newVehicles.length > 0 ? this.renderVehicles(newVehicles) : html``}
                        `;
                    },
                })}
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

    async handleReconnectClick(vin: string, vehicleTokenId: number) {
        // Run the onboarding flow with the vehicleTokenId
        // This will trigger: VerifyVins → GetMintData → SubmitMintData → Finalize
        this.onboardVehicleTask.run([vin, vehicleTokenId]);
    }
}
