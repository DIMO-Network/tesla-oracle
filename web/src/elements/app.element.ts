import {css, html, LitElement, unsafeCSS} from 'lit'
import {customElement} from "lit/decorators.js";

// @ts-ignore
import styles from '@styles/main.css?inline'

@customElement('app-element')
export class AppElement extends LitElement {
    static styles = css`${unsafeCSS(styles)}`;

    render() {
        return html`
            <div class="grid grid-cols-2 gap-4">
                <div>
                   <p>Welcome to DIMO Tesla Oracle</p>
                </div>
            </div>
        `;
    }
}
