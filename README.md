# PyFind
<p align="center">
  <img src="https://github.com/MaxBubblegum47/PyFind/blob/main/docs/PyFind_logo.PNG" alt="Project logo" width="200px">
</p>


Pyfind is a project based on:
1. Who Can Find My Devices? Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking System 
(https://arxiv.org/abs/2103.02282)
2. The Clever Cryptography Behind Apple's 'Find My' Feature (https://www.wired.com/story/apple-find-my-cryptography-bluetooth/)
3. How does Apple (privately) find your offline devices? (https://blog.cryptographyengineering.com/2019/06/05/how-does-apple-privately-find-your-offline-devices/)
4. WWDC 2019 Keynote - Apple (https://www.youtube.com/watch?v=psL_5RIBqnY&t=6711s) [1:50:00]

The aim is to recreate in Python the "Find My Device Feature" that was first presented during the WWDC 2019. Most of the project is based on the first documented that I have linked. Since a real Apple's documentation is still missing, this is the closest thing we have.

To test the project you can ```git clone``` the repo, positioning inside ```/src``` folder and type the following commands:
```bash
pip install requirements.txt
python3 FindMyDevice.py
```
This simulates the eventually of losing your own iPhone, but there's also another simulation in which you are searching an airtag: ```FindMyDevice_Airtag.py```