# NetworkSecurityF23
  
### RUN AS BROKER:  
`make broker` OR `python sockets.py --mode broker`  
  
### RUN AS CLIENT:  
`make client` OR `python sockets.py --mode client`  
  
### RUN AS MERCHANT:  (Pending)  
`make merchant` OR `python sockets.py --mode merchant`  
  
### Configuring defaults:  
Use `config` file to define default IP and ports for each mode.  
Also provides many configuration values that can be changed.    
  
### References:  
- https://realpython.com/python-sockets/
- https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
- https://docs.python.org/3/howto/sockets.html
- https://www.markdownguide.org/cheat-sheet/
- https://realpython.com/intro-to-python-threading/
    
### NOTES:
- It may take sometime for the "server" (i.e. port) to be released. Program may give error saying its not available.
- Built with python version: `Python 3.10.12`
  
