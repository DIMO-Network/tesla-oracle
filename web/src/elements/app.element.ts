import {css, html, LitElement, unsafeCSS} from 'lit'
import {customElement, state} from "lit/decorators.js";
import {repeat} from 'lit/directives/repeat.js';
import {Message, MessageService} from "@services/message.service.ts";

// @ts-ignore
import styles from '@styles/main.css?inline'


@customElement('app-element')
export class AppElement extends LitElement {
    static styles = css`${unsafeCSS(styles)}`;

    private messageService = MessageService.getInstance();

    @state() messages: Message[] = [];

    connectedCallback() {
        super.connectedCallback();

        this.messageService.registerHandler("message", this.onMessage.bind(this))
        this.messageService.registerHandler("sign", this.onMessage.bind(this))
        this.messageService.registerHandler("signature", this.onMessage.bind(this))

        this.messageService.sendMessage({type: "message", data: "Hello from Tesla Oracle UI"})
    }

    private onMessage(message: Message) {
        console.debug(message);
        this.messages = [...this.messages, message]; // .push won't trigger re-render
    }

    render() {
        return html`
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <p>Welcome to DIMO Tesla Oracle</p>
                    <div>
                        <button class="button" type="button">Send a message</button>
                        <button class="button" type="button">Send sign request</button>
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
                </div>
            </div>
        `;
    }
}
