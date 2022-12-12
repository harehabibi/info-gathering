# info-gathering
Info gathering from list of host name
just create txt file from your target(s)
you should put one hostname in every line without any character such as , or ; or ...
this tools check this item for every host
  a) resolve IP address
  b) check ping
  c) check http request and its response and redirection
  d) check https request and its response and redirection
  c) nmap scan to detect operation system, open ports and host status
  
 result file contain this columns
 
| Target Host | Target IP | Ping Status | HTTP Response Code | HTTP GET Request | HTTP_DETAILS | HTTP_REDIRECTION | HTTPS Response Code | HTTPS GET REQUEST | HTTPS_DETAILS | HTTPS_REDIRECTION | NMAP_OS | NMAP_PORT | NMAP_HOST_STATE  
 
 yout can copy all raw in result text file and paste in excel sheet and then use "Text to Column" tools to put every column in object on one cell
  
this tools is useful when you want to assesment a lots of domain for penetration test.
