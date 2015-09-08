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

For a good "Getting Started" guide on using threat_note, check out [this](http://www.cyintanalysis.com/playing-with-threat_note/) post by [@CYINT_dude](https://twitter.com/CYINT_dude) on his blog.

### Screenshots

First up is a shot of the dashboard, which has the latest indicators, the latest starred indicators, and a campaign and indicator type breakdown.

<p align="center">
<img src="http://i.imgur.com/hWknd2C.png" href="http://i.imgur.com/hWknd2C.png"></p>

Next is a screenshot of the Network Indicators page, here you will see all the indicators that have a type of "Domain", "Network", or "IP Address". 

<p align="center">
<img src="http://i.imgur.com/uSaLH6y.png" href="http://i.imgur.com/uSaLH6y.png"></p>

You can edit or remove the indicator right from this page, by hovering over the applicable icon on the right-hand side of the indicator.

<p align="center">
<img src="http://i.imgur.com/ovzUgBV.png" href="http://i.imgur.com/ovzUgBV.png"></p>

Clicking on a network indicator will pull up the details page for the indicator. If you have Whois information turned on, you'll see the city and country underneath the indicator.

<p align="center">
<img src="http://i.imgur.com/7DsYbgl.png" href="http://i.imgur.com/7DsYbgl.png"></p>

Clicking on the "New Indicator" button on the Network or Threat Actor page will bring up a page to enter details about your new indicator.

<p align="center">
<img src="http://i.imgur.com/m6hQswB.png" href="http://i.imgur.com/m6hQswB.png"></p>

If you click on the "Edit Indicator" icon next to an indicator, you'll be presented with a page to edit any of the details you previously entered. You can also click on the "New Attribute" icon at the bottom right to add a new attribute to your indicator.

<p align="center">
<img src="http://i.imgur.com/W3LShn7.png" href="http://i.imgur.com/W3LShn7.png"></p>

In the screenshot below you can see the "Threat Actors" page, which is similiar to the "Network Indicators" page, however, you'll only be presented with the Threat Actors you've entered.

<p align="center">
<img src="http://i.imgur.com/8KgVPRW.png" href="http://i.imgur.com/8KgVPRW.png"></p>

Below is the Campaign page. It contains all of your indicators, broken out by campaign name. **Please note that the "Edit Description" button to the right of the campaign description is broken right now, and will be fixed in a future release.** Clicking on an indicator will take you to the indicator detail page.

<p align="center">
<img src="http://i.imgur.com/CUBmvXz.png" href="http://i.imgur.com/CUBmvXz.png"></p>

Lastly, here is the Settings page, where you can delete your threat_note database, as well as control any 3rd party integrations, such as Whois data or VirusTotal information. Turning these integrations on can slow down the time to retrieve details about your indicator. 

<p align="center">
<img src="http://i.imgur.com/vrBEu9F.png" href="http://i.imgur.com/vrBEu9F.png"></p>

### Credits

Thanks to the guys over at [Creative Tim](http://www.creative-tim.com/) for their awesome Bootstrap theme. Download your version for free [here](http://demos.creative-tim.com/light-bootstrap-dashboard). 

### License

This software is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2015 Brian Warehime, Defense Point Security, LLC.
