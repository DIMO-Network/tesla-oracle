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
        email: '',
    };

    connectedCallback() {
        super.connectedCallback();

        this.shadowRoot?.addEventListener(AuthEventType.LOGOUT, () => {
            this.logout();
        });

        if (this.parseQueryString()) {
            history.pushState(null, '', '/');
        }

        const token = this.getToken();
        const email = this.getEmail();

        if (token) {
            this._auth = { ...this._auth, token, email};
        } else {
            this.logout();
        }
    }

    render() {
        return html`<slot></slot>`;
    }

    logout() {
        console.debug('LOGOUT');

        this._auth = { ...this._auth, token: '', email: ''};

        const keysToRemove = ['token', 'email'];
        keysToRemove.forEach(key => {
            localStorage.removeItem(key);
        });
    }

    parseQueryString() {
        const params = new URLSearchParams(window.location.search);
        let hadParams = false;
        console.debug('QS Params:');
        params.forEach((value, key) => {
            console.debug(`${key}: ${value}`);
            if (['email', 'token'].includes(key)) {
                localStorage.setItem(key, value);
                hadParams = true;
            }
        });

        return hadParams;
    }

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

    getEmail() {
        return localStorage.getItem("email") || '';
    }
}
