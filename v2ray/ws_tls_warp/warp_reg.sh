#!/usr/bin/expect -f

spawn warp-cli register
expect {
    "(yes/no)?" {
        send "yes\n"
    }
}
interact