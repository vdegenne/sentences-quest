import {createSlice, PayloadAction} from '@reduxjs/toolkit'
import { User } from 'firebase/auth'

export const userIs = {
  INDETERMINATE: 'indeterminate',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected'
} as const;

export interface UserState {
  is: typeof userIs[keyof typeof userIs],
  uid?: string
}

const initialState = {
  is: userIs.INDETERMINATE
} as UserState

const userSlice = createSlice({
  name: 'app',
  initialState,
  reducers: {
    setUid (state, action: PayloadAction<string|undefined>) {
      state.uid = action.payload
      state.is = action.payload ? 'connected' : 'disconnected'
    }
  }
})


export const {setUid} = userSlice.actions
export default userSlice.reducer