# Kodi-Event-Notifier
Python script that implements an email gateway/proxy service to notify Kodi on an incoming event message.

Other than my previous script Kodi-Email-Alert, this script will not purely act as an email client waiting for messages being delivered from your Mail Service Provider, but rather implement its own (simple) SMTP gateway.

The advantage of this solution is, once the sending device is configured with the data of your SMTP gateway, it will send messages directly to it. This avoids the additional delay when messages are sent to your MSP first and then get redelivered to you, thus allowing the instant processing of their contained information. This is extremely useful if you don’t want to rely on other instant notification measures such as Passive IR motion sensors etc.

I’m using this script for my dahua web cams that are sending automatic alert messages when motion is detected in the cams’ attention zone. The incoming alert message triggers the sending of a GUI notification and the execution of a corresponding add-on (defaults to script.securitycam but is configurable with start parameter -a/--addonid) on my Kodi hosts.

Furthermore, the incoming message can be forwarded preserving its original subject and - if available - attachments. Since the SMTP gateway uses only login authentication as a basic security measure and does not validate the recipient list of the incoming message, the message can be forwarded to the addressees configured in the incoming message. Optionally, a new subject line and recipient list can be specified for the forwarded messages that overwrites the original information.

Since my cams are sending messages to also notify me of a motion detection stop event, I’m using this script as an email filter for suppressing those unwanted messages. You may also filter for other information such as the sending device’s name or IP address or a specific alert event as long as this information is included and clearly identifiable in the original message body. As I wanted this script to be usable also with other devices I made these filters configurable in the required kodi_event_notifier.ini file (see kodi_event_notifier.ini.template file for more details) in which you also configure your Kodi host addresses, login credentials and port number for your SMTP gateway as well as the credentials to be used when forwarding messages via your MSP.

For example, if your device is sending an event notification message containing the following information in the message body:
```
Alarm Event: Motion Detection
Alarm Device Name: DOOR_CAM
IP Address: 10.10.30.6
```
If you want to filter for this specific event sent from this device, you would configure these entries in kodi_event_notifier.ini:
```
event: Alarm Event
eventid: Motion Detection
device: Alarm Device Name
deviceid: DOOR_CAM
```
Alternatively, you could filter for the IP address by configuring:
```
device: IP address
deviceid: 10.10.30.6
```
In case you have multiple device sending event notification, you can specify a comma separated list of deviceids.

In case your device does not send attachments, you may configure a directory which is searched for files to use as attachments in the forwarded message. Optionally, configure a local command to be executed before sending, e.g. for producing the file attachements in the search directory. 

I wanted this script to run as a 24x7 background service on my raspberry pi, so I provided a unit file kodi_event_notifier.service which can be installed in /etc/systemd/system to run the script automatically on startup.
