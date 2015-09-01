<p align="center">
<img src="http://i.imgur.com/4keZTGz.png"></p>

### Disclaimer 

Please note threat_note is in beta at the moment, and you may experience issues with this app. This was tested on Yosemite 10.10.4 running Google Chrome, other browsers or OS'es may experience issues with the rendering, please identify any issues or possible fixes to the issues page.

### About

threat_note is a web application built by [Defense Point Security](http://www.defpoint.com) to allow security researchers the ability to add and retrieve indicators related to their research. As of right now this includes the ability to add IP Addresses, Domains and Threat Actors, with more types being added in the future.

This app fills the gap between various solutions currently available, by being lightweight, easy-to-install, and by minimizing fluff and extraneous information that sometimes gets in the way of adding information. To create a new indicator, you only really need to supply the object itself (whether it be a Domain, IP or Threat Actor) and change the type accordingly, and boom! That's it! Of course, supplying more information is definitely helpful, but, it's not required. 

Other applications built for storing indicators and research have some shortcomings that threat_note hopes to fix. Some common complaints with other apps are:

- Hard to install/configure/maintain
- Need to pay for added features (enterprise licenses)
- Too much information
  - This boils down to there being so much stuff to do to create new indicators or trying to cram a ton of functions inside the app.

### Installation

As this tool tries to be lightweight and easy to setup, we tried to make the setup as easy as possible. To get started, you'll need to install [Vagrant](https://www.vagrantup.com/) along with a provider (Using VirtualBox is recommended since it's free and available on all platforms and already built into Vagrant.)

That's it! By using Vagrant it'll save you the time and hassle of configuring your own server and database. This Vagrant machine sets up the Mongo database you'll need in order for threat_note to store your indicators as well as sets up the Flask Python app that runs the web server.

So, if you have Vagrant installed on your machine, simply run the following:

```
cd threat_note/vagrant
vagrant up
```

If you don't get any errors, you can just browse to http://localhost:7777 and you'll have yourself a brand new threat_note server to start populating.

### Usage

For a good "Getting Started" guide on using threat_note, check out this post by [@CYINT_dude](https://twitter.com/CYINT_dude) on his blog, which you can read [here](http://www.cyintanalysis.com/playing-with-threat_note/).

### Screenshots

Below is a screenshot of the "New Indicator" page, here you can enter as many or as few details about your indicator as you'd like. 

<p align="center">
<img src="http://i.imgur.com/GbumDll.png" href="http://i.imgur.com/GbumDll.png"></p>

The settings page, where you can turn on and configure your 3rd part integrations.

<p align="center">
<img src="http://i.imgur.com/0xn1dk2.png" href="http://i.imgur.com/0xn1dk2.png"></p>

The page below is the indicator page for an indicator already created. Here you can edit it, delete it, or "star" it (when you "star" the indicator, it will be highlighted in the "Indicators" pages). 

<p align="center">
<img src="http://i.imgur.com/wa3l0qW.png" href="http://i.imgur.com/wa3l0qW.png"></p>

Below is a shot of what a "favorited" indicator looks like in the "networks" page.

<p align="center">
<img src="http://i.imgur.com/LhzdYHs.png" href="http://i.imgur.com/LhzdYHs.png"></p>

Next is a shot of the overview page, which has the latest indicators, the latest starred indicators, and a campaign and indicator type breakdown.

<p align="center">
<img src="http://i.imgur.com/iQMSvDD.png" href="http://i.imgur.com/iQMSvDD.png"></p>

### License

This software is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2015 Brian Warehime, Defense Point Security, LLC.
