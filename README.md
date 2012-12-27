pamalt - PaloAlto Network appliances Maltego Transforms
=======================================================

Author: David Bressler
twitter: @bostonlink

## 1.0 - ABOUT

pamalt is a project that integrates the PAN web API to create Maltego transforms.  This functionality gives the ability to Information Security Teams and SOCs the ability to graph and create Machines (Maltego Radium) to view the threat landscape of an organization.  

## 2.0 - INSTALLATION

### 2.1 - [Linux/OSX]

pamalt depends on Python 2.7.3

1. Clone the pamalt git repository
2. Move the pamalt repository to the /opt directory
3. chown the pamalt directory 'chown -R user:group pamalt' (optional)
4. Import the imports/pamalt_config.mtz into Maltego
5. Edit the /opt/pamalt/pamalt/conf/pamalt.conf file with the proper credentials 
6. You're ready to rock and roll =)

### 2.2 - [Windows]

pamalt depends on Python 2.7.3

1. Clone the pamalt git repository
2. Copy the pamalt folder to the root of the C:\ (ex: C:\pamalt\)
3. If the zip file was downloaded change the name of the folder within the root of the C:\ drive from pamalt-master to pamalt
4. Import the pamalt_win_config.mtz configuration file into Maltego
5. Edit the C:\pamalt\pamalt\conf\pamalt.conf file with the proper credentials
6. Should be ready to rock and roll, test,test,test!

## SPECIAL THANKS!

Rich Popson (@Rastafari0728)
* Drinking Partner, Stay Frosty!
* QA Tester
* Idea Contributor

Paterva (@Paterva)
* For creating Maltego to begin with =)

MassHackers (@MassHackers)
* Boston Hacking Community!! Join the list and come to a meeting!
