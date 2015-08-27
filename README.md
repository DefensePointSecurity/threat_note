<p align="center">
<img src="http://i.imgur.com/4keZTGz.png"></p>

### Disclaimer 

Please note threat_note is in beta at the moment, and you may experience issues with this app. This was tested on Yosemite 10.10.4 running Google Chrome, other browsers or OS'es may experience issues with the rendering, please identify any issues or possible fixes to the issues page.

### About

threat_note is a web application built by [Defense Point Security](http://www.defpoint.com) to allow security researchers the ability to add and retrieve indicators related to their research. As of right now this includes the ability to add IP Addresses, Domains and Threat Actors, with more types being added in the future.

This app fills the gap between various solutions currently available, by being lightweight, easy-to-install, and by minimizing fluff and extraneous information that sometimes gets in the way of adding information. To create a new indicator, you only really need to supply the object itself (whether it be a Domain, IP or Threat Actor) and change the type accordingly, and boom! That's it! Of course, supplying more information is definitely helpful, but, it's not required. 

Other applications built for storing indicators and research have some shortcomings that threat_note hopes to fix. Some common complaints with other apps are:

- Hard to install/configure
- Need to pay for added features (enterprise licenses)
- Too much information
  - This boils down to there being so much stuff to do to create new indicators or trying to cram a ton of functions inside the app.

### Installation

As this tool tries to be lightweight and easy to setup, we tried to make the setup as easy as possible. To get started, you'll need to install [Vagrant](https://www.vagrantup.com/) along with a provider (Using VirtualBox is recommended since it's free and available on all platforms and already built into Vagrant.)

That's it! By using Vagrant it'll save you the time and hassle of configuring your own server and database. This Vagrant machine sets up the Mongo database you'll need in order for threat_note to store your indicators as well as sets up the Flask Python app that runs the web server.

So, if you have Vagrant installed on your machine, simply run the following:

```
cd vagrant
vagrant up
```

If you don't get any errors, you can just browse to http://localhost:7777 and you'll have yourself a brand new threat_note server to start populating.
