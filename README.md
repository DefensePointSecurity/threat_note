<p align="center">
<img src="http://i.imgur.com/4keZTGz.png"></p>

### Disclaimer

Please note threat_note is in beta at the moment, and you may experience issues with this app. This was tested on Yosemite 10.10.4 running Google Chrome, other browsers or OS'es may experience issues with the rendering, please identify any issues or possible fixes to the issues page.

### Version 3 Release Notes

Major changes include:

- Switched back-end database to SQLite
- Removed Vagrant machine needed for Mongo
- Added ThreatCrowd Visualization Integration
- Added basic authentication system (user can register/login)
- Settings and Profile pages moved to user account dropdown

...and many minor bug fixes

### About

threat_note is a web application built by [Defense Point Security](http://www.defpoint.com) to allow security researchers the ability to add and retrieve indicators related to their research. As of right now this includes the ability to add IP Addresses, Domains and Threat Actors, with more types being added in the future.

This app fills the gap between various solutions currently available, by being lightweight, easy-to-install, and by minimizing fluff and extraneous information that sometimes gets in the way of adding information. To create a new indicator, you only really need to supply the object itself (whether it be a Domain, IP or Threat Actor) and change the type accordingly, and boom! That's it! Of course, supplying more information is definitely helpful, but, it's not required.

Other applications built for storing indicators and research have some shortcomings that threat_note hopes to fix. Some common complaints with other apps are:

- Hard to install/configure/maintain
- Need to pay for added features (enterprise licenses)
- Too much information
  - This boils down to there being so much stuff to do to create new indicators or trying to cram a ton of functions inside the app.

### Installation

Now that we are using SQLite, there's no need for a pesky Vagrant machine. All we need to do is install some requirements via pip and fire up the server:

```
cd threat_note
pip install -r requirements.txt
honcho start
```

Once the server is running, you can browse to http://localhost:5000 and register a new account to use to login into threat_note with.

### Docker Installation

A development dockerfile is now available, to build it do the following from its directory:

```
sudo docker build -t threat_note .
sudo docker run -itd -p 8888:8888 threat_note
```

Once the server is running, you can browse to http://localhost:8888 and register a new account to use to login into threat_note with.

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

Lastly, here is the Settings page, where you can delete your threat_note database, as well as control any 3rd party integrations, such as Whois data or VirusTotal information. Turning these integrations on can slow down the time to retrieve details about your indicator. A new feature recently added by [@alxhrck](https://github.com/alxhrck) was the ability to add an HTTP(s) proxy if you need it to connect to 3rd parties. He also recently added support for a new 3rd party integration, OpenDNS Investigate, which can be activated on this page.

<p align="center">
<img src="http://i.imgur.com/AwRYkEI.png" href="http://i.imgur.com/AwRYkEI.png"></p>

### Credits

Thanks to the guys over at [Creative Tim](http://www.creative-tim.com/) for their awesome Bootstrap theme. Download your version for free [here](http://demos.creative-tim.com/light-bootstrap-dashboard).

### License

This software is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2015 Brian Warehime, Defense Point Security, LLC.
