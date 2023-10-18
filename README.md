# NetworkSecurityF23
  
### RUN AS BROKER:  
`python sockets.py --mode broker`  
  
### RUN AS CLIENT:  
`python sockets.py --mode client`  
  
### RUN AS MERCHANT:  (Pending)  
`python sockets.py --mode merchant`  
  
### Configuring defaults:  
Use `config` file to define default IP and ports for each mode.  
  
### TODO:  
1. Merge 2 ports into single port for each mode.
2. Test how broker can receive from customer and send to merchant at the same time? Does it need additional code refactoring to call them async-ly?
3. Do we need to split each into separate files?
4. How clean does the code need to be? Any points for this? :)
5. ISSUE: If broker is started with a `port!=config-port` => client does not connect as it tries to connect a wrong port. We will need to pass the target broker IP/port as cmd args as well.
6. TODO: Makefile to incorporate the mode and args.
7. TODO: (Very Later) Add Client2. (Extra: socket logic needs to handle parallel connections? - Async?)
8. Generate requirements.txt to lock-in python and module versions?
  
### References:  
- https://realpython.com/python-sockets/
- https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
- https://docs.python.org/3/howto/sockets.html
    
### NOTES:
- It may take sometime for the "server" / "listening" port to be released. Program may give error saying its not available.
- Built with python version: `Python 3.10.12`
  
