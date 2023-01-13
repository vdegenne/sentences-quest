import { LitElement, html, css, RootPart, PropertyValueMap, unsafeCSS, nothing } from 'lit'
import { customElement, state } from 'lit/decorators.js'
import { Router } from '@lit-labs/router'
import { auth } from './firebase.js'
import { connect } from 'pwa-helpers'
import { RootState, store } from './redux/store.js'
import { signOut, User } from 'firebase/auth'
import appStyles from './styles/AppContainerStyles.css'
import { userIs, UserState } from './redux/user.js'

@customElement('app-container')
export class AppContainer extends connect(store)(LitElement) {

  @state()
  private user!: UserState;

  private _router = new Router(this,
    [
      { path: '/', render: () => html`sweet home` },
      { path: '/details', render: () => html`boom` },
      { path: '/login', render: () => html`<login-view></login-view>` }
    ],
    { fallback: { render: () => html`404` } }
  )

  stateChanged(state: RootState) {
    this.user = {...state.user}
  }

  static styles = [unsafeCSS(appStyles)]

  render () {
    return html`
    ${this.user.is == userIs.INDETERMINATE ? html`
    <mwc-circular-progress indeterminate></mwc-circular-progress>
    ` : nothing}

    ${this.user?.uid ? html`
      <mwc-button @click=${() => signOut(auth)}>logout</mwc-button>
    ` : nothing}

    ${this.user.is != userIs.INDETERMINATE ? html`
    <div>${this._router.outlet()}</div>
    ` : nothing}
    `
  }

  protected updated(_changedProperties: PropertyValueMap<any> | Map<PropertyKey, unknown>): void {
    if (_changedProperties.has('user')) {
      this.onUserChange()
    }
  }

  async goto (url: string)  {
  }
  async onUserChange () {
    console.log(this.user, window.location.pathname)
    if (this.user.is == userIs.DISCONNECTED && window.location.pathname !== '/login') {
      let url = '/login'
      const params = new URLSearchParams(window.location.search)
      params.append('origin', window.location.pathname)
      url += `?${params.toString()}`
      window.history.pushState({}, '', url)
      await this._router.goto('/login')
    }

    // user logged in from the login page
    if (this.user.is == userIs.CONNECTED && window.location.pathname === '/login') {
      const params = new URLSearchParams(window.location.search)
      if (params.has('origin')) {
        const origin = decodeURIComponent(params.get('origin'))
        window.history.pushState({}, '', origin)
        await this._router.goto(origin)
      }
    }
  }
}