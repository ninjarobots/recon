# recon
oscp recon scripts

## Requirements

``` bash
sudo apt install python3-nmap
```

## Usage
### Start the server
``` bash
sudo python3 recond_server.py --host 192.168.xxx.xxx --port 5000 ~/<lab name>
```

### Web Page
- Navigate to \<host\>:\<port\> 
- Add your target ips to the list
- Start the scans

### Notes
In the \<lab name\> directory you will find notes for each of the hosts that were enumerated

These are just a good starting point for an obsidian note page for each host


