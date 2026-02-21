# IDS MVP - Needs a ton of work

This is my basic version of intrusion detection system.
This is not useable now only main.py works and that only filters and informs the attacks on specified threats.
Usually UDP, ACK and other flood thresholds are set way above what I have set in this program for the sake of testing where normally UDP flood hovering around 1500 to 2000 pps (packet per second). ICMP usually goes 200-1000 which can be customized too. HTTP request storms and DNS floods were added later; HTTP floods are detected based on request rate. Other high-volume ones hover around 3000-5000. This program is just a proof of concept for the actual Intrusion Detection System. I will be adding more features shortly afterwards.

## Usecase:

```
sudo python3 main.py
```
This starts the main python file that has all the functions including the blacklist sources and destinations and flood detection. 

I have intentionally added router IPs as blacklist source IPs to trigger alerts for you to make it easy to understand.