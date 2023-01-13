import { signInWithPopup } from 'firebase/auth';
import { html, LitElement } from 'lit';
import { customElement } from 'lit/decorators.js';
import { auth, googleAuthProvider } from '../firebase.js';

@customElement('login-view')
export class LoginView extends LitElement {
  render () {
    return html`
    <mwc-button raised @click=${this._onClick}>Login with Google</mwc-button>
    `
  }

  private _onClick () {
    signInWithPopup(auth, googleAuthProvider)
  }
}