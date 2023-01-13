// Import the functions you need from the SDKs you need
import { initializeApp } from 'firebase/app';
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries
import {getAuth, GoogleAuthProvider} from 'firebase/auth'
import {getFirestore} from 'firebase/firestore'
import { store } from './redux/store.js';
import { setUid } from './redux/user.js';

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyB-wf3OHvzlkPY7oQO3GTYBlrNbijdwLSk",
  authDomain: "sentences-quest.firebaseapp.com",
  projectId: "sentences-quest",
  storageBucket: "sentences-quest.appspot.com",
  messagingSenderId: "152001033544",
  appId: "1:152001033544:web:ba1a0791e98aa0d0656f7d"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig)
export const auth = getAuth(app)
export const db = getFirestore(app)


export const googleAuthProvider = new GoogleAuthProvider();

let firstCall = true
auth.onAuthStateChanged((user) => {
  if (firstCall) {
    // @ts-ignore
    // appRoot.innerHTML = '<app-container></app-container>'
    firstCall = false
  }
  if (!user) {
    store.dispatch(setUid(undefined))
    return
  }
  store.dispatch(setUid(user.uid))
})