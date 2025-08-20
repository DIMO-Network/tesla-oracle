import {LitElement, html} from 'lit';
import {provide} from '@lit/context';

import {AuthContext, authContext, AuthEventType} from '@context/auth.context';
import {customElement, property} from "lit/decorators.js";

@customElement('auth-provider')
export class AuthProvider extends LitElement {
    @provide({context: authContext})
    @property({attribute: false})
    private _auth: AuthContext = {
        token: '',
        vehicleTokenId: '',
    };

    // this is a lit lifecycle event that gets called when the web component loads (ie. page load).
    connectedCallback() {
        super.connectedCallback();

        this.shadowRoot?.addEventListener(AuthEventType.LOGOUT, () => {
            this.logout();
        });

        if (this.parseQueryString()) {
            history.pushState(null, '', '/');
        }

        const token = this.getToken();

        if (token) {
            this._auth = { ...this._auth, token};
        } else {
            this.logout();
        }
    }

    render() {
        return html`<slot></slot>`;
    }

    logout() {
        console.debug('LOGOUT');

        this._auth = { ...this._auth, token: '', vehicleTokenId: ''};

        const keysToRemove = ['token', 'vehicleTokenId'];
        keysToRemove.forEach(key => {
            localStorage.removeItem(key);
        });
    }

    // when the webview is open from the mobile app, this is called to get the dimo JWT and optionally vehicle token id
    parseQueryString() {
        const params = new URLSearchParams(window.location.search);
        let hadParams = false;
        console.debug('QS Params:');
        params.forEach((value, key) => {
            console.debug(`${key}: ${value}`);
            if (['token', 'vehicleTokenId'].includes(key)) {
                localStorage.setItem(key, value);
                hadParams = true;
            }
        });

        return hadParams;
    }

    // gets the DIMO JWT and check that it is not expired, from localstorage.
    getToken() {
        const token = localStorage.getItem("token");
        if (!token) {
            console.debug("No token found");
            return null; // If there's no token, treat it as expired
        }

        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const currentTime = Math.floor(Date.now() / 1000);
            return payload.exp < currentTime ? null : token;
        } catch (error) {
            console.error("Invalid token:", error);
            return null;
        }
    }
}
