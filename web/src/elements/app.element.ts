import {css, html, LitElement, unsafeCSS} from 'lit'
import {customElement} from "lit/decorators.js";
import {MessageService} from "@services/message.service.ts";

// @ts-ignore
import styles from '@styles/main.css?inline'
import {SigningService} from "@services/signing.service.ts";

// this is the main app
@customElement('app-element')
export class AppElement extends LitElement {
    static styles = css`${unsafeCSS(styles)}`;

    private messageService = MessageService.getInstance();
    private signingService = SigningService.getInstance();

    connectedCallback() {
        super.connectedCallback();

        this.signingService.useMessageService(this.messageService);
        this.messageService.sendMessage({type: "message", data: "Hello from Tesla Oracle UI"})
    }

    render() {
        return html`
            <div>
                <h2 class="text-2xl font-semibold mb-6">Connect your Tesla</h2>
                <tesla-element></tesla-element>
            </div>
        `;
    }
}
