import {LitElement, html} from 'lit';
import {provide} from '@lit/context';

import {customElement, property} from "lit/decorators.js";
import {TeslaAuthContext, teslaAuthContext} from "@context/tesla-auth.context.ts";


@customElement('tesla-auth-provider')
export class AuthProvider extends LitElement {
    @provide({context: teslaAuthContext})
    @property({attribute: false})
    private _auth: TeslaAuthContext = {
        code: '',
        locale: '',
        state: '',
        issuer: '',
    };

    connectedCallback() {
        super.connectedCallback();
        this._auth = {
            ...this._auth,
            state: this.createRandomState(),
        }

        if (this.parseQueryString()) {
            history.pushState(null, '', '/');
        }
    }

    render() {
        return html`<slot></slot>`;
    }

    parseQueryString() {
        const params = new URLSearchParams(window.location.search);

        let hadParams = false;

        console.debug('QS Params:');
        params.forEach((value, key) => {
            console.debug(`${key}: ${value}`);
            if (['locale', 'code', 'state', 'issuer'].includes(key)) {
                localStorage.setItem(key, value);
                this._auth = {...this._auth, [key]: value}
                hadParams = true;
            }
        });

        return hadParams;
    }

    createRandomState() {
        const array = new Uint32Array(10);
        return crypto.getRandomValues(array).toString();
    }
}
