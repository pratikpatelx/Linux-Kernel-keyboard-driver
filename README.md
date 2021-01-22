# Linux-Kernel-keyboard-driver
A linux kernel module that is a keyboard driver only supports shift and plain keys. This was an Operating System Assignment for the operating systems course at the University.

# Usage

TO COMPILE and LOAD THE MODULE TYPE THE FOLLOWING COMMANDS ON TERMINAL:

    make build
    sudo insmod keybuff.ko or insmod keybuff.ko if you are the root
    
TO RUN THE CODE TYPE:
    open terminal and be the root and type the following
    sudo tail -f /var/log/messages
    
    type any letter or key on the keyboard, you will see a message on the terminal showing what key was pressed
    
    then navigate to 
    /proc/keybuff file and do a cat keybuff on it to see the previously keys typed

# Dependencies
This program only runs on Linux Operating System
