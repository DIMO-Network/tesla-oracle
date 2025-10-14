import {css, html, LitElement, unsafeCSS} from 'lit'
import {customElement, state} from "lit/decorators.js";
import {repeat} from 'lit/directives/repeat.js';
import {Message, MessageService} from "@services/message.service.ts";

// @ts-ignore
import styles from '@styles/main.css?inline'
import {SignatureMessageData, SigningService} from "@services/signing.service.ts";

// this is the debug app with all test buttons
@customElement('app-debug-element')
export class AppDebugElement extends LitElement {
    static styles = css`${unsafeCSS(styles)}`;

    private messageService = MessageService.getInstance();
    private signingService = SigningService.getInstance();

    @state() messages: Message[] = [];
    @state() signatures: SignatureMessageData[] = [];

    connectedCallback() {
        super.connectedCallback();

        this.messageService.registerHandler("message", this.onMessage.bind(this))
        this.signingService.useMessageService(this.messageService);

        this.messageService.sendMessage({type: "message", data: "Hello from Tesla Oracle UI"})
    }

    private onMessage(message: Message) {
        console.debug('on message', message);
        this.messages = [...this.messages, message]; // .push won't trigger re-render
    }

    // test sending a message to validate we can communicate with the wrapping mobile app
    handleSendMessage() {
        this.messageService.sendMessage({type: 'message', data: 'Message from Orache UI'})
    }

    // test signing request with typed data to validate the mobile app is triggering the signing. This does not mint or perform any action. SACD type, uploads to ipfs etc.
    async handleSignRequest() {
        const data = {
            types: {
                EIP712Domain: [
                    { name: 'name', type: 'string' },
                    { name: 'version', type: 'string' },
                    { name: 'chainId', type: 'uint256' },
                    { name: 'verifyingContract', type: 'address' },
                ],
                MintVehicleWithDeviceDefinitionSign: [
                    {name: "manufacturerNode", type: "uint256"},
                    {name: "owner", type: "address"},
                    {name: "deviceDefinitionId", type: "string"},
                    {name: "attributes", type: "string[]"},
                    {name: "infos", type: "string[]"},
                ]
            },
            domain: {
                name: 'DIMO',
                version: '1',
                chainId: 8002,
                verifyingContract: '0x5eAA326fB2fc97fAcCe6A79A304876daD0F2e96c',
            },
            primaryType: 'MintVehicleWithDeviceDefinitionSign',
            message: {
                manufacturerNode: 128,
                owner: '0x0000000000000000000000000000000000000000',
                deviceDefinitionId: 'toyota_hilux_2023',
                attributes: ["Make", "Model", "Year"],
                infos: ["Toyota", "Hilux", "2023"],
            }
        }

        try {
            const signatureData = await this.signingService.signMintTypedData(data)
            this.signatures = [...this.signatures, signatureData];
        } catch (e) {
            console.error(e);
        }
    }

    render() {
        return html`
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <p>Welcome to DIMO Tesla Oracle</p>
                    <div>
                        <button class="button" type="button" @click=${this.handleSendMessage}>Send a message</button>
                        <button class="button" type="button" @click=${this.handleSignRequest}>Send sign request</button>
                        <tesla-debug-element></tesla-debug-element>
                    </div>
                    <br/>
                    <br/q>
                    <div>
                        <h2>Received messages (${this.messages.length}):</h2>
                    </div>
                    <div>
                        ${repeat(this.messages, (_, i) => i, (item) => html`
                             <div class="font-mono">${JSON.stringify(item)}</div>`)}
                    </div>
                    <div>
                        <h2>Signatures:</h2>
                    </div>
                    <div>
                        ${repeat(this.signatures, (_, i) => i, (item) => html`
                             <div class="font-mono">${JSON.stringify(item)}</div>`)}
                    </div>
                </div>
            </div>
        `;
    }
}
