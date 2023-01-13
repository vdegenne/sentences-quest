#!/bin/bash

session='test'

tmux new -d -s $session 'npx firebase emulators:start'

tmux split-window -h 'npm run browser-sync'
#tmux split-window -h 'npm run browser-sync'

#tmux split-window -f

#tmux send-keys 'pm2 start pm2.config.cjs' C-m

tmux attach-session -t $session:0
