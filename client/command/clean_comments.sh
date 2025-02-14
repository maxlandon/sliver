grep -rl '<<<<<<<' --include=*.go . | xargs sed -i '/<<<<<<<.*$/,/>>>>>>>.*$/ { /^\s*\/\/.*\.$/d }'
grep -rl '<<<<<<< HEAD' --include=*.go . | xargs sed -i '/<<<<<<< HEAD$/,/=======/d'
grep -rl '<<<<<<< HEAD' --include=*.go . | xargs sed -i '/<<<<<<< HEAD$/,/>>>>>>> master/d'
