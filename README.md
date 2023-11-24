# NetworkSecurityF23
  
### RUN AS BROKER:  
`make broker` OR `python sockets.py --mode broker`  
  
### RUN AS CLIENT:  
`make client` OR `python sockets.py --mode client`  
  
### RUN AS MERCHANT:  (Pending)  
`make merchant` OR `python sockets.py --mode merchant`  
  
### Configuring defaults:  
Use `config` file to define default IP and ports for each mode.  
  
### TODO:  
1. ~~Merge 2 ports into single port for each mode.~~    Done.
2. Test how broker can receive from customer and send to merchant at the same time? Does it need additional code refactoring to call them async-ly?     -> API based approach, "operation" will define what is to be done.
3. Do we need to split each into separate files? If it helps in modularity / readability.
4. How clean does the code need to be? Any points for this? :)
5. ISSUE: If broker is started with a `port!=config-port` => client does not connect as it tries to connect a wrong port. We will need to pass the target broker IP/port as cmd args as well.
6. TODO: Makefile to incorporate the mode and args. currently only supports defaults.
7. ~~(Very Later) Add Client2. (Extra: socket logic needs to handle parallel connections? - Async?)~~   Done.
8. Generate requirements.txt to lock-in python and module versions? -> External installations covered
9. IMP: TODO: Try-Catch when a socket connection is dropped?
10. ~~IMP: Try-Catch for KeyBoard interrupts.~~     Done.
  
### References:  
- https://realpython.com/python-sockets/
- https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
- https://docs.python.org/3/howto/sockets.html
- https://www.markdownguide.org/cheat-sheet/
    
### NOTES:
- It may take sometime for the "server" (i.e. port) to be released. Program may give error saying its not available.
- Built with python version: `Python 3.10.12`
  
