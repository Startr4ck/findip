# Find ip
Use some online methods to find the real IP address behind the CDN     
DNS resolution
Website analysis without www
Use the same icon, title, website certificate, etc.    

# Hint  
You can choose to use the API to search in the program, or you can choose not to use the API.
If you need an API, you need to configure it in config.txt, which includes the APIs of censys and shodan.
*censysy security_trail’s API is free*
The specific implementation can be found in the source code configuration.

## Background
In realworld pentest .We need to know the real ip address behind CDN protect so that we can do some exploit.This tool automatical do that thing!  

The above is all nonsense. The real situation is that I need a graduation project, so I wrote a program that is barely usable 2333

## Install
``` 
git clone https://github.com/Startr4ck/findip.git
python3 -r requirments.txt 
```

## Usage
python3 stats2.py 
or 
release stats2

## Show 
![image](https://github.com/Startr4ck/findip/blob/master/show.gif)   


## What still needs to be done
* Packager 打包程序 
* Optimize speed 优化速度 
