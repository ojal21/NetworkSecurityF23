# NetworkSecurityF23
  
### BUILD:  
Built with python version: `Python 3.10.12`  
Install additional dependencies with `pip3 -r requirements.txt`  

### User configuration:  
- Please use `python3 add-client.py` to save the username and password in broker's list.  
- Please create folder with the username under `client/purchased/` folder   
- Please create the RSA key pair and add to `client/keys` and `broker/keys` folders appropriately.  
  
### RUN AS BROKER:  
`make broker` OR `python3 sockets.py --mode broker`  
  
### RUN AS CLIENT:  
`make client` OR `python3 sockets.py --mode client`  
  
### RUN AS MERCHANT:  
`make merchant` OR `python3 sockets.py --mode merchant`  
  
### NON DEFAULT MODE:  
Each (server) mode can be run with user defined ip and port without changing config file:  
`python3 sockets.py --mode merchant --ip 127.0.0.1 --port 55555`  

### Configuring defaults:  
Use `config` file to define default IP and ports for each mode. Also provides many runtime configuration values that can be changed:    
- broker share/commission percentage
- broker account number
- merchant account number (at broker)
- different password hash file
- file padding length
- product amount

  
### References:  
- https://realpython.com/python-sockets/
- https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
- https://docs.python.org/3/howto/sockets.html
- https://www.markdownguide.org/cheat-sheet/
- https://realpython.com/intro-to-python-threading/
    
### NOTES:
- It may take sometime for the "server" (i.e. port) to be released. Program may give error saying its not available.
  
