import './firebase.js'
import '@material/mwc-snackbar'
import '@material/mwc-button'
import '@material/mwc-circular-progress'
import { AppContainer } from './main.js';
// import '@material/mwc-icon-button'
// import '@material/mwc-dialog'
// import '@material/mwc-textfield'
// import '@material/mwc-checkbox'

import './main.js'
import './views/login-view.js'

import './redux/store.js'

declare global {
  interface Window {
    app: AppContainer;
    toast: (labelText: string, timeoutMs?: number) => void;
  }
}