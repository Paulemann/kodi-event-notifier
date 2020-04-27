#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from datetime import datetime
import requests
import json

import logging
import configparser
import os
import sys
import socket
import signal
import subprocess

import email
from email.utils import formataddr
from email.header import Header, decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
import smtplib

import argparse

import base64
import asyncore
from smtpd import SMTPServer, SMTPChannel, DEBUGSTREAM

# global settings
_max_waittime_ = 10


def is_mailaddress(a):
  try:
    t = a.split('@')[1].split('.')[1]
  except:
    return False

  return True


def is_hostname(h):
  try:
    t = h.split('.')[2]
  except:
    return False

  return True


def is_int(n):
  try:
    t = int(n)
  except:
    return False

  return True


def log(message, level='INFO'):
  if _log_file_:
    if level == 'DEBUG' and _debug_:
      logging.debug(message)
    if level == 'INFO':
      logging.info(message)
    if level == 'WARNING':
      logging.warning(message)
    if level == 'ERROR':
      logging.error(message)
    if level == 'CRITICAL':
      logging.crtitcal(message)
  else:
     if level != 'DEBUG' or _debug_:
       print('[{:^8}] '.format(level) + message)


def read_config():
  global _kodi_hosts_, _kodi_port_, _kodi_user_, _kodi_passwd_
  global _login_user_, _login_passwd_
  global _event_port_, _event_key_, _event_id_, _event_device_key_, _event_device_id_, _event_description_, _event_stream_id_
  global _smtp_server_, _smtp_realname_, _smtp_user_, _smtp_passwd_
  global _mail_to_, _mail_subject_, _mail_overwrite_, _mail_body_, _mail_attach_, _time_fmt_
  global _notify_title_, _notify_text_, _exec_local_

  if not os.path.exists(_config_file_):
    log('Could not find configuration file \'{}\'.'.format(_config_file_), level='ERROR')
    return False

  log('Reading configuration from file ...')

  config = configparser.ConfigParser(interpolation=None)
  config.read([os.path.abspath(_config_file_)], encoding='utf-8')
  try:
    # Read the config file
    #config = configparser.ConfigParser(interpolation=None)
    #config.read([os.path.abspath(_config_file_)], encoding='utf-8')

    _kodi_hosts_        = [p.strip(' "\'') for p in config.get('KODI JSON-RPC', 'hostname').split(',')]
    _kodi_port_         = int(config.get('KODI JSON-RPC', 'port').strip(' "\''))
    _kodi_user_         = config.get('KODI JSON-RPC', 'username').strip(' "\'')
    _kodi_passwd_       = config.get('KODI JSON-RPC', 'password').strip(' "\'')

    for host in _kodi_hosts_:
      if not is_hostname(host):
        log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC]).')
        return False

    if not is_int(_kodi_port_):
      log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC]).')
      return False

    _login_user_        = config.get('Login', 'username').strip(' "\'')
    _login_passwd_      = config.get('Login', 'password').strip(' "\'')

    _event_port_        = int(config.get('Event', 'port').strip(' "\''))
    _event_key_         = config.get('Event', 'event').strip(' "\'')
    _event_id_          = config.get('Event', 'eventid').strip(' "\'')
    # Allow multiple events as trigger
    #_event_id_          = [p.strip(' "\'') for p in config.get('Event', 'eventid').split(',')]
    _event_device_key_  = config.get('Event', 'device').strip(' "\'')
    _event_device_id_   = [p.strip(' "\'') for p in config.get('Event', 'deviceid').split(',')]
    _event_description_ = [p.strip(' "\'') for p in config.get('Event', 'description').split(',')]

    if not is_int(_event_port_):
      log('Wrong or missing value(s) in configuration file (section: [Event]).')
      return False

    try:
      _event_stream_id_   = [int(p.strip(' "\'')) for p in config.get('Event', 'streamid').split(',')]
    except:
      _event_stream_id_   = []

    if _event_stream_id_:
      for id in _event_stream_id_:
        if not is_int(id):
          log('streamid value(s) not of type integer in configuration file (section: [Event]).')
          return False

    _smtp_server_    = config.get('Mail Account', 'smtpserver').strip(' "\'')
    _smtp_realname_  = config.get('Mail Account', 'realname').strip(' "\'')
    _smtp_user_      = config.get('Mail Account', 'username').strip(' "\'')
    _smtp_passwd_    = config.get('Mail Account', 'password').strip(' "\'')

    if is_hostname(_smtp_server_):
      if not is_mailaddress(_smtp_user_) or not _smtp_passwd_:
        log('Wrong or missing value(s) in configuration file (section [Mail Account]).')
        return False

      try:
        _mail_to_        = [p.strip(' "\'') for p in config.get('Alert Mail', 'recipient').split(',')]
        _mail_subject_   = config.get('Alert Mail', 'subject').strip(' "\'')
        _mail_overwrite_ = True

        for addr in _mail_to_:
          if not is_mailaddress(addr):
            log('Wrong or missing value(s) in configuration file (section [Alert Mail]).')
            return False

        if not _mail_subject_ or not _mail_body_:
          log('Wrong or missing value(s) in configuration file (section [Alert Mail]).')
          return False
      except:
        _mail_to_        = []
        _mail_subject_   = ''
        _mail_overwrite_ = False
        log('Missing entries \'subject\' and \'recipient\' in section [Alert Mail]. Using data from original message.', level='DEBUG')

      _mail_body_      = config.get('Alert Mail', 'text').strip(' "\'').replace('\\n', '\r\n')
      _mail_attach_    = [p.strip() for p in config.get('Alert Mail', 'attach').split(',')]
      _time_fmt_       = config.get('Alert Mail', 'timeformat').strip(' "\'')

      if _mail_attach_ == ['']:
        _mail_attach_ = None

      if _time_fmt_ == '':
        _time_fmt_ = "%Y-%m-%d %H:%M:%S"

    _notify_title_   = config.get('Alert Notification', 'title').strip(' "\'')
    _notify_text_    = config.get('Alert Notification', 'text').strip(' "\'')

    _exec_local_     = config.get('Local', 'command').strip(' "\'')

  except:
    log('Could not process configuration file.', level='ERROR')
    return False

  log('Configuration OK.')

  return True


def kodi_request(host, method, params):
  url  = 'http://{}:{}/jsonrpc'.format(host, _kodi_port_)
  headers = {'content-type': 'application/json'}
  data = {'jsonrpc': '2.0', 'method': method, 'params': params,'id': 1}

  if _kodi_user_ and _kodi_passwd_:
    base64str = base64.encodestring('{}:{}'.format(_kodi_user_, _kodi_passwd_))[:-1]
    header['Authorization'] = 'Basic {}'.format(base64str)

  try:
    response = requests.post(url, data=json.dumps(data), headers=headers, timeout=10)
  except:
    return False

  data = response.json()
  return (data['result'] == 'OK')


def host_is_up(host, port):
  try:
    sock = socket.create_connection((host, port), timeout=3)
  #except socket.timout:
  #  return False
  except:
    return False

  return True


def sendmail(recipients, subject, message, attachments=None):
  #
  # https://code.tutsplus.com/tutorials/sending-emails-in-python-with-smtp--cms-29975
  #

  if not message:
    return False

  msg = MIMEMultipart()

  if _smtp_realname_:
    msg['From']  = formataddr((str(Header(_smtp_realname_, 'utf-8')), _smtp_user_))
  else:
    msg['From']  = _smtp_user_
  msg['To']      = ', '.join(recipients)
  msg['Subject'] = subject

  log('Assembling message with subject \'{}\' ...'.format(msg['Subject']), level='DEBUG')

  msg.attach(MIMEText(message, 'plain'))

  for name, content in attachments or []:
    log('Processing attachment: {} ...'.format(name), level='DEBUG')
    try:
      if not content and os.path.isfile(name):
        with open(name, 'rb') as f:
          payload = f.read()
      elif content:
        payload = content
      else:
        continue
      part = MIMEBase('application', "octet-stream")
      part.set_payload(payload)
      email.encoders.encode_base64(part)
      part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(os.path.basename(name)))
      msg.attach(part)
    except:
      log('Couldn\'t process attachment. Proceeding ...', level='DEBUG')
      continue

  try:
    server = smtplib.SMTP(_smtp_server_)
    server.starttls()
    server.login(_smtp_user_, _smtp_passwd_)
    server.sendmail(_smtp_user_, msg['To'].split(','), msg.as_string())
    log('Message successfully sent to recipient(s): {}.'.format(msg['To']))

  except:
    log('Failed sending message.', level='ERROR')
    return False

  finally:
    server.quit()

  return True


def alert(device_id, attachments=None):
  # This will execute  the configured local command passing the device id as add. argument
  # Attention: Script waits for command to terminate and return
  if not attachments and _exec_local_:
    try:
      log('Executing local command: {} {} ...'.format(_exec_local_, device_id), level='DEBUG')
      parms = _exec_local_.split()
      parms.append(device_id)
      subprocess.call(parms)
    except Exception as e:
      log('Excution failed with exception: \'{}\'. Proceeding ...'.format(e), level='ERROR')
      pass

  for host in _kodi_hosts_:
    log('Initiating communication with kodi host: {} ...'.format(host))

    if not host_is_up(host, _kodi_port_):
      log('Host is down. Action(s) canceled.', level='DEBUG')
      continue

    if _notify_title_ and _notify_text_:
      try:
        text = _notify_text_.format(_event_description_[_event_device_id_.index(device_id)])
      except:
        text = _notify_text_

      log('Sending notification \'{}: {}\' ...'.format(_notify_title_, text), level='DEBUG')
      kodi_request(host, 'GUI.ShowNotification', {'title': _notify_title_, 'message': text, 'displaytime': 2000})

    if _addon_id_:
      if _event_stream_id_ and len(_event_stream_id_) == len(_event_device_id_) and device_id:
        stream_id = _event_stream_id_[_event_device_id_.index(device_id)]
      else:
        stream_id = 0

      log('Callling addon \'{}\' for stream id {} ...'.format(_addon_id_, stream_id), level='DEBUG')
      kodi_request(host, 'Addons.ExecuteAddon', {'addonid': _addon_id_, 'params': {'streamid': str(stream_id)}})

  if _smtp_server_:
    # In case of test, recipients and subject may be empty
    if not _mail_to_:
      recipients = [_smtp_user_]
    else:
      recipients = _mail_to_

    try:
      subject = _mail_subject_.format(_event_description_[_event_device_id_.index(device_id)])
    except:
      subject = _mail_subject_

    if not subject:
      subject = 'Test'

    try:
      now = datetime.now().strftime(_time_fmt_)
      body = '{}: '.format(now) + _mail_body_.format(_event_description_[_event_device_id_.index(device_id)])
    except:
      body = _mail_body_

    files = attachments
    if not files and _mail_attach_ and os.path.isdir(_mail_attach_[0]):
      log('Searching directory for attachment(s): {} ...'.format(_mail_attach_[0]), level='DEBUG')
      waittime = 0
      while not next(os.walk(_mail_attach_[0]))[2] and waittime < _max_waittime_:
        waittime += 1
        time.sleep(1)

      p = _mail_attach_[0]
      files = [(os.path.join(p, f), None) for f in sorted(os.listdir(p)) if os.path.isfile(os.path.join(p, f))]
      log('Found {} file(s) to attach.'.format(len(files)), level='DEBUG')
    elif files:
      log('Forwarding {} attachment(s) from original message ...'.format(len(files)), level='DEBUG')

    log('Sending message via {} ...'.format(_smtp_server_.split(':')[0]), level='DEBUG')
    sendmail(recipients, subject, body, files)


def decode_b64(data):
  """Wrapper for b64decode, without having to struggle with bytestrings."""
  byte_string = data.encode('utf-8')
  decoded = base64.b64decode(byte_string)
  return decoded.decode('utf-8')


def encode_b64(data):
  """Wrapper for b64encode, without having to struggle with bytestrings."""
  byte_string = data.encode('utf-8')
  encoded = base64.b64encode(byte_string)
  return encoded.decode('utf-8')


class FakeCredentialValidator(object):
  def __init__(self, username, password, channel):
    self.username = username
    self.password = password
    self.channel = channel

  def validate(self):
    log('Receiving authentication request for user: {} ...'.format(self.username), level='DEBUG')

    if self.username == _login_user_ and self.password == _login_passwd_:
      log('Authentication successful.', level='DEBUG')
      return True

    log('Authentication failed.', level='ERROR')
    return False


class MySMTPChannel(SMTPChannel):
  credential_validator = FakeCredentialValidator

  def __init__(self, server, conn, addr, *args, **kwargs):
    super().__init__(server, conn, addr, *args, **kwargs)
    self.username = None
    self.password = None
    self.authenticated = False
    self.authenticating = False

  def smtp_AUTH(self, arg):
    if 'PLAIN' in arg:
      split_args = arg.split(' ')
      # second arg is Base64-encoded string of blah\0username\0password
      authbits = decode_b64(split_args[1]).split('\0')
      self.username = authbits[1]
      self.password = authbits[2]
      if self.credential_validator and self.credential_validator(self.username, self.password, self).validate():
        self.authenticated = True
        self.push('235 Authentication successful.')
      else:
        self.push('454 Temporary authentication failure.')
        self.close_when_done()

    elif 'LOGIN' in arg:
      self.authenticating = True
      split_args = arg.split(' ')

      # Some implmentations of 'LOGIN' seem to provide the username
      # along with the 'LOGIN' stanza, hence both situations are
      # handled.
      if len(split_args) == 2:
        self.username = decode_b64(arg.split(' ')[1])
        self.push('334 ' + encode_b64('Username'))
      else:
        self.push('334 ' + encode_b64('Username'))

    elif not self.username:
      self.username = decode_b64(arg)
      self.push('334 ' + encode_b64('Password'))

    else:
      self.authenticating = False
      self.password = decode_b64(arg)
      if self.credential_validator and self.credential_validator(self.username, self.password, self).validate():
        self.authenticated = True
        self.push('235 Authentication successful.')
      else:
        self.push('454 Temporary authentication failure.')
        self.close_when_done()

  def smtp_EHLO(self, arg):
    if not arg:
      self.push('501 Syntax: EHLO hostname')
      return
    if self.seen_greeting:
      self.push('503 Duplicate HELO/EHLO')
      return
    self._set_rset_state()
    self.seen_greeting = arg
    self.extended_smtp = True
    self.push('250-{}'.format(self.fqdn))
    self.push('250-AUTH LOGIN PLAIN')
    self.push('250-AUTH LOGIN PLAIN')
    if self.data_size_limit:
      self.push('250-SIZE {}'.format(self.data_size_limit))
      self.command_size_limits['MAIL'] += 26
    if not self._decode_data:
      self.push('250-8BITMIME')
    if self.enable_SMTPUTF8:
      self.push('250-SMTPUTF8')
      self.command_size_limits['MAIL'] += 10
    self.push('250 HELP')

  def smtp_HELO(self, arg):
    if not arg:
      self.push('501 Syntax: HELO hostname')
      return
    if self.seen_greeting:
      self.push('503 Duplicate HELO/EHLO')
      return
    self._set_rset_state()
    self.seen_greeting = arg
    self.push('250 {}'.format(self.fqdn))

  def run_command_with_arg(self, command, arg):
    method = getattr(self, 'smtp_' + command, None)
    if not method:
       self.push('500 Error: command "{}" not recognized'.format(command))
       return

    # White list of operations that are allowed prior to AUTH.
    if command not in ['AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT']:
      if not self.authenticated:
        self.push('530 Authentication required')
        return

    method(arg)

  def found_terminator(self):
    line = self._emptystring.join(self.received_lines)
    print('Data:', repr(line), file=DEBUGSTREAM)
    self.received_lines = []
    if self.smtp_state == self.COMMAND:
      sz, self.num_bytes = self.num_bytes, 0
      if not line:
        self.push('500 Error: bad syntax')
        return
      if not self._decode_data:
        line = str(line, 'utf-8')
      i = line.find(' ')

      if self.authenticating:
        # If we are in an authenticating state, call the
        # method smtp_AUTH.
        arg = line.strip()
        command = 'AUTH'
      elif i < 0:
        command = line.upper()
        arg = None
      else:
        command = line[:i].upper()
        arg = line[i + 1:].strip()
      max_sz = (self.command_size_limits[command] if self.extended_smtp else self.command_size_limit)

      if sz > max_sz:
        self.push('500 Error: line too long')
        return

      self.run_command_with_arg(command, arg)
      return
    else:
      if self.smtp_state != self.DATA:
        self.push('451 Internal confusion')
        self.num_bytes = 0
        return
      if self.data_size_limit and self.num_bytes > self.data_size_limit:
        self.push('552 Error: Too much mail data')
        self.num_bytes = 0
        return
      # Remove extraneous carriage returns and de-transparency according
      # to RFC 5321, Section 4.5.2.
      data = []
      for text in line.split(self._linesep):
        if text and text[0] == self._dotsep:
          data.append(text[1:])
        else:
          data.append(text)
      self.received_data = self._newline.join(data)
      args = (self.peer, self.mailfrom, self.rcpttos, self.received_data)
      kwargs = {}
      if not self._decode_data:
        kwargs = {
          'mail_options': self.mail_options,
          'rcpt_options': self.rcpt_options,
        }
      status = self.smtp_server.process_message(*args, **kwargs)
      self._set_post_data_state()
      if not status:
        self.push('250 OK')
      else:
        self.push(status)


class MySMTPServer(SMTPServer):
  channel_class = MySMTPChannel

  def process_message(self, peer, mailfrom, rcpttos, data):
    global _mail_to_, _mail_subject_

    try:
      #Implement additional security checks here: e.g. filter on mailfrom and/or addr.
      addr, port = peer
      log('Receiving message from: {}:{}'.format(addr, port))
      log('Message sent from:      {}'.format(mailfrom))
      log('Message addressed to:   {}'.format(', '.join(rcpttos)))

      msg = email.message_from_string(data)
      subject = ''
      for encoded_string, charset in decode_header(msg.get('Subject')):
        try:
          if charset is not None:
            subject += encoded_string.decode(charset)
          else:
            subject += encoded_string
        except:
          log('Error reading part of subject: {} charset {}'.format(encoded_string, charset))
      log('Message subject:        {}'.format(subject))

      if not _mail_overwrite_: #Maintain subject and recipient list from original message
        _mail_to_ = rcpttos
        _mail_subject_ = subject

      headers = '\n\t'.join((str(key) + ': ' + str(val)) for key, val in msg.items())
      log('Message headers:\n\t' + headers, level='DEBUG')

      text_parts = []
      #attachments = {}
      attachments = []

      # loop on the email parts
      for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
          continue

        c_type = part.get_content_type()
        c_disp = part.get('Content-Disposition')

        # text parts will be appended to text_parts
        if c_type == 'text/plain' and c_disp == None:
          text_parts.append(part.get_payload(decode=True).decode('utf-8').strip())
        # ignore html part
        elif c_type == 'text/html':
          continue
        # attachments will be sent as files in the POST request
        else:
          filename = part.get_filename()
          filecontent = part.get_payload(decode=True)
          if filecontent is not None:
            if filename is None:
              #filename = 'untitled'
              filename = 'untitled{}'.format(len(attachments))
            #attachments['file{}'.format(len(attachments))] = (filename, filecontent)
            attachments.append((filename, filecontent))
            log('Message attachment: file{} = {}'.format(len(attachments), filename), level='DEBUG')

      body = '\r\n'.join(text_parts)

      lines = '\n\t'.join([l.strip() for l in body.split('\r')])
      log('Message body:\n\t' + lines, level='DEBUG')

      event_data =  {}
      for line in [l.strip() for l in body.split('\r')]:
        line = line.replace(': ', '= ')
        args = [p.strip() for p in line.rsplit('=', 1)]
        if len(args) == 2:
          event_data[args[0]] = args[1]

      if not _event_key_ or not _event_id_:
        log("No event configured for processing.", level='ERROR')
        return

      if _event_key_ not in event_data:
        log("No data to identify this event.", level='ERROR')
        return

      if _event_device_key_ and _event_device_id_:
        if _event_device_key_ not in event_data:
          log("No data to identify this device.", level='ERROR')
          return
        if event_data[_event_device_key_] not in _event_device_id_:
          log("Not processing events from this device.", level='DEBUG')
          return

      if event_data[_event_key_] in _event_id_:
        log("Message has alarm event: {}.".format(_event_id_))
        alert(event_data[_event_device_key_], attachments=attachments)
      else:
        log("Message has no event to process.", level='DEBUG')

    except:
      log('Error reading incoming message', level='ERROR')


def port_is_used(port):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    return s.connect_ex(('localhost', port)) == 0


if __name__ == '__main__':
  global _config_file_, _log_file_, _addon_id_, _debug_, _test_

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host and triggers addon execution on receipt of an external 433 MHz signal')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  parser.add_argument('-l', '--logfile', dest='log_file', default=None, help="Path to log file (Default: None=stdout)")
  parser.add_argument('-c', '--config', dest='config_file', default=os.path.splitext(os.path.basename(__file__))[0] + '.ini', help="Path to config file (Default: <Script Name>.ini)")
  parser.add_argument('-a', '--addonid', dest='addon_id', default='script.securitycam', help="Addon ID (Default: script.securitycam)")
  parser.add_argument('-t', '--test', dest='test', action='store_true', help="Test Alert (Default: False)")

  args = parser.parse_args()

  _config_file_ = args.config_file
  _log_file_ = args.log_file
  _addon_id_ = args.addon_id
  _debug_ = args.debug
  _test_  = args.test

  if _log_file_:
    logging.basicConfig(filename=_log_file_, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='w', level=logging.DEBUG)

  log('Output Debug: {}'.format(_debug_), level='DEBUG')
  log('Log file:     {}'.format(_log_file_), level='DEBUG')
  log('Config file:  {}'.format(_config_file_), level='DEBUG')
  log('Addon ID:     {}'.format(_addon_id_), level='DEBUG')

  if not read_config():
    sys.exit(1)

  if _test_: # Simulate event and send test message to _smtp_user_
    log('Simulating event ...')
    alert(_event_device_id_[0])
    sys.exit(0)

  # Start the smtp server on port _event_port_
  if not port_is_used(_event_port_):
    log('Listening for event messages on port {} ...'.format(_event_port_))
    smtp_server = MySMTPServer(('0.0.0.0', _event_port_), None)
  else:
    log('Port {} is already in use.'.format(_event_port_), level='ERROR')
    sys.exit(1)

  try:
    asyncore.loop()

  except (KeyboardInterrupt, SystemExit):
    log('Abort requested by user or system.', level='DEBUG')
    sys.exit(1)

  except Exception as e:
    log('Abort due to exception: \'{}\''.format(e), level='ERROR')
    sys.exit(1)

  finally:
    smtp_server.close()
