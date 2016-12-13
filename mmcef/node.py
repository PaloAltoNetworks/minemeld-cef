import logging
import os
from datetime import datetime

import yaml
from gevent.socket import socket, AF_INET, SOCK_DGRAM
from pytz import utc

from girolamo import Template
from minemeld.ft.base import BaseFT, _counting

from . import __version__

LOG = logging.getLogger(__name__)


_SYSLOG_LEVELS = {
    'KERN': 0,
    'USER': 1,
    'MAIL': 2,
    'DAEMON': 3,
    'AUTH': 4,
    'SYSLOG': 5,
    'LPR': 6,
    'NEWS': 7,
    'UUCP': 8,
    'CRON': 9,
    'AUTHPRIV': 10,
    'FTP': 11,
    'LOCAL0': 16,
    'LOCAL1': 17,
    'LOCAL2': 18,
    'LOCAL3': 19,
    'LOCAL4': 20,
    'LOCAL5': 21,
    'LOCAL6': 22,
    'LOCAL7': 23
}

_SYSLOG_FACILITIES = {
    'EMERG': 0,
    'ALERT': 1,
    'CRIT': 2,
    'ERR': 3,
    'WARNING': 4,
    'NOTICE': 5,
    'INFO': 6,
    'DEBUG': 7
}

# list of attributes that should be provided by template
# if not set filtered_update will fail
_CEF_HEADER_FIELDS = [
    'deviceVendor',
    'deviceProduct',
    'deviceVersion',
    'deviceEventClassID',
    'Name',
    'Severity'
]


class Output(BaseFT):
    def __init__(self, name, chassis, config):
        self.parent_template = os.path.join(
            os.path.dirname(__file__),
            'templates/cef.yml'
        )
        self.locals = {
            'version': __version__
        }

        super(Output, self).__init__(name, chassis, config)

        self.socket = None

    def configure(self):
        super(Output, self).configure()

        self.verify_cert = self.config.get('verify_cert', True)
        self.host = self.config.get('host', None)
        self.port = self.config.get('port', 514)
        self.template = self.config.get('template', None)

        level_ = self.config.get('level', 'SYSLOG')
        self.level = _SYSLOG_LEVELS.get(level_.upper(), None)
        if self.level is None:
            raise ValueError('Unknown syslog level {}'.format(level_))

        facility_ = self.config.get('facility', 'INFO')
        self.facility = _SYSLOG_FACILITIES.get(facility_, None)
        if self.facility is None:
            raise ValueError('Unknown syslog facility {}'.format(facility_))

        self.lf_encoded = self.level+self.facility*8

        self._compile_template()

        self._build_socket()

    def _compile_template(self):
        with open(self.parent_template, 'r') as f:
            template = yaml.safe_load(f)

        self._compiled_template = Template.compile(template)

    def _build_socket(self):
        if self.host is None or self.port is None:
            LOG.error('{}: host or port not set'.format(self.name))
            return

        if self.socket is not None:
            self.socket.close()

        # XXX add support for TCP
        self.socket = socket(AF_INET, SOCK_DGRAM)

    def connect(self, inputs, output):
        output = False
        super(Output, self).connect(inputs, output)

    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    def _cef_header_escape(self, s):
        if '\\n' in s or '\\r' in s:
            raise ValueError('Newline in header field: {!r}'.format(s))

        s = s.replace('\\', '\\\\')
        s = s.replace('|', '\\|')

        return s

    def _cef_extension_key_escape(self, s):
        if '\\n' in s or '\\r' in s:
            raise ValueError('Newline in extension key: {!r}'.format(s))

        s = s.replace('\\', '\\\\')
        s = s.replace('=', '\\=')

        return s

    def _cef_extension_value_escape(self, s):
        s = s.replace('\\', '\\\\')
        s = s.replace('=', '\\=')
        s = s.replace('\n', '\\n')
        s = s.replace('\r', '\\r')

        return s

    def _emit_cef(self, fields):
        fields['deviceEventClassID'] = self.name

        cef_fields = ['CEF:0']  # CEF version 0

        for cef_field in _CEF_HEADER_FIELDS:
            cef_fields.append(
                self._cef_header_escape(fields.pop(cef_field))
            )

        # everything else goes into the extension
        extension_field = []
        for k, v in fields.iteritems():
            if v is None:
                continue

            extension_field.append(
                '{}={}'.format(
                    self._cef_extension_key_escape(k),
                    self._cef_extension_value_escape(v)
                )
            )

        if len(extension_field) == 0:
            cef_fields.append('')
        else:
            cef_fields.append(' '.join(extension_field))

        cef_message = '|'.join(cef_fields)

        LOG.debug('{}: emit {}'.format(self.name, cef_message))

        timestamp = datetime.utcnow().replace(tzinfo=utc)

        # XXX check if the 3164 does not really include year and TZ
        syslog_msg = '<{}>{} {}'.format(
            self.lf_encoded,
            timestamp.strftime('%b %d %H:%M:%S'),
            cef_message
        )

        # XXX add support for TCP
        if self.socket is not None:
            self.socket.sendto(syslog_msg, (self.host, self.port))

        self.statistics['message.sent'] += 1

    @_counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        value['__indicator'] = indicator
        value['__method'] = 'update'
        output = self._compiled_template.eval(locals_=self.locals, data=value)
        self._emit_cef(output)

    @_counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        value['__indicator'] = indicator
        value['__method'] = 'withdraw'
        output = self._compiled_template.eval(locals_=self.locals, data=value)
        self._emit_cef(output)

    def length(self, source=None):
        return 0
