import logging
import os
import hashlib
from datetime import datetime
from collections import defaultdict

import yaml
import netaddr
from gevent import socket, sleep, Greenlet, GreenletExit
from gevent.socket import SOCK_DGRAM, SOCK_STREAM, IPPROTO_TCP
from gevent.queue import Queue, Full
from pytz import utc

from girolamo import Template
from minemeld.ft.base import _counting
from minemeld.ft.actorbase import ActorBaseFT

VERSION = "0.1"

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

_PROTOCOLS = {
    'TCP': SOCK_STREAM,
    'UDP': SOCK_DGRAM
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


class SyslogActor(Greenlet):
    def __init__(self, name, maxsize=10000):
        super(SyslogActor, self).__init__()
        self._queue = Queue(maxsize=maxsize)
        self._socket = None
        self.name = name
        self.address_info = None
        self.host = None
        self.port = None
        self.protocol = None
        self.statistics = defaultdict(int)

    def set_address(self, host, port, protocol):
        self.host = host
        self.port = port
        self.protocol = protocol

        self.address_info = None

        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def put(self, msg):
        try:
            self._queue.put(msg, block=False, timeout=0)
        except Full:
            self.statistics['message.drop'] += 1

    def _resolve_address(self):
        if self.host is None or self.port is None or self.protocol is None:
            LOG.error('{}: host, port or protocol not set'.format(self.name))
            self.address_info = None
            return False

        protocol_ = _PROTOCOLS.get(self.protocol.upper(), None)
        if protocol_ is None:
            LOG.error('{}: unknown protocol {}'.format(self.name, self.protocol.upper()))
            self.address_info = None
            return False

        try:
            self.address_info = socket.getaddrinfo(self.host, self.port, 0, protocol_)[0]
        except (IndexError, socket.error) as e:
            LOG.error(
                '{}: error resolving {}:{}: {}'.format(self.name, self.host, self.port, str(e))
            )
            self.address_info = None
            return False

        LOG.info('{}: syslog server resolved to {!r}'.format(self.name, self.address_info))

        return True

    def _build_socket(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None

        if not self._resolve_address():
            raise RuntimeError('Error resolving syslog server address')

        self._socket = socket.socket(*self.address_info[:3])
        self._socket.connect(self.address_info[4])

    def _ship(self, msg):
        while True:
            try:
                if self._socket is None:
                    self._build_socket()

                self._socket.send(
                    msg+('\n' if self.address_info[2] == IPPROTO_TCP else '')  # we add "framing" if on TCP
                )
                self.statistics['cef-message.tx'] += 1
                return

            except (RuntimeError, socket.error) as e:
                if self._socket is not None:
                    self._socket.close()
                    self._socket = None

                LOG.error('{}: error sending msg to syslog: {}'.format(self.name, str(e)))
                self.statistics['error.sending'] += 1
                sleep(seconds=60)

    def _run(self):
        while True:
            msg = self._queue.get()
            LOG.info('{}: from queue {}'.format(self.name, msg))

            try:
                self._ship(msg)
                LOG.info('returned')

            except GreenletExit:
                break

            except:
                LOG.exception('Exception in CEF output actor')
                sleep(60)

            if self.statistics['cef-message.tx'] % 8192 == 1:
                sleep(0.001)

    def length(self):
        return self._queue.qsize()

    def kill(self):
        if self._socket is not None:
            self._socket.close()
        super(SyslogActor, self).kill()


class Output(ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.parent_template = os.path.join(
            os.path.dirname(__file__),
            'templates/cef.yml'
        )
        self.locals = {
            'version': VERSION
        }

        self._actor = None

        super(Output, self).__init__(name, chassis, config)

        self._actor = SyslogActor(self.name, maxsize=self.queue_maxsize)
        self._actor.set_address(self.host, self.port, self.protocol)

    def configure(self):
        super(Output, self).configure()

        self.queue_maxsize = int(self.config.get('queue_maxsize', 100000))
        if self.queue_maxsize == 0:
            self.queue_maxsize = None

        self.host = self.config.get('host', None)
        self.port = self.config.get('port', 514)
        self.protocol = self.config.get('protocol', 'TCP')

        level_ = self.config.get('level', 'SYSLOG')
        self.level = _SYSLOG_LEVELS.get(level_.upper(), None)
        if self.level is None:
            raise ValueError('Unknown syslog level {}'.format(level_))

        facility_ = self.config.get('facility', 'INFO')
        self.facility = _SYSLOG_FACILITIES.get(facility_, None)
        if self.facility is None:
            raise ValueError('Unknown syslog facility {}'.format(facility_))

        self.pri = self.level+self.facility*8

        self.external_id = self.config.get('external_id', 'MineMeld')

        self.template = self.config.get('template', None)
        if self.template is None:
            self.template = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_template.yml' % self.name
            )

        self._compile_template()

    def _compile_template(self):
        # basically everyt time this node starts checks the template
        # - if it does not exist, the template provided in the package
        #   is copied over and the md5 is added at the top as watermark
        # - if it exists, the watermark is checked. If intact and matches
        #   the md5 of the template in the package all good. If the watermark
        #   it's not intact or does not match the one in the package, the
        #   template in the package is copied over.
        # This way we can update templates using code updates, but only if
        # this does not override local customizations
        with open(self.parent_template, 'r') as f:
            parent_template = f.read()
        parent_md5 = hashlib.md5(parent_template)

        if self._old_template(parent_md5, self.template):
            with open(self.template, 'w') as f:
                f.write('# {}\n'.format(parent_md5.hexdigest()))
                f.write(parent_template)

        with open(self.template, 'r') as f:
            template = yaml.safe_load(f)

        self._compiled_template = Template.compile(template)

    def _old_template(self, new_md5, path):
        if not os.path.exists(path):
            LOG.info('file does not exist')
            return True

        with open(path, 'r') as f:
            shebang = f.readline().strip()

            if len(shebang) < 34:
                return False

            if shebang[:2] != '# ':
                return False

            orig_template_md5 = shebang[2:]
            template_md5 = hashlib.md5(f.read())

        if orig_template_md5 != template_md5.hexdigest():
            return False

        return template_md5 != new_md5

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
        if not isinstance(s, str) and not isinstance(s, unicode):
            return u'{}'.format(s)

        if '\\n' in s or '\\r' in s:
            raise ValueError('Newline in header field: {!r}'.format(s))

        s = s.replace('\\', '\\\\')
        s = s.replace('|', '\\|')

        return s

    def _cef_extension_key_escape(self, s):
        if not isinstance(s, str) and not isinstance(s, unicode):
            raise ValueError('{}: extension keys should be strings'.format(self.name))

        if '\\n' in s or '\\r' in s:
            raise ValueError('Newline in extension key: {!r}'.format(s))

        s = s.replace('\\', '\\\\')
        s = s.replace('=', '\\=')

        return s

    def _cef_extension_value_escape(self, s):
        if not isinstance(s, str) and not isinstance(s, unicode):
            return u'{}'.format(s)

        s = s.replace('\\', '\\\\')
        s = s.replace('=', '\\=')
        s = s.replace('\n', '\\n')
        s = s.replace('\r', '\\r')

        return s

    def _emit_cef(self, fields):
        fields['deviceProcessName'] = self.name
        fields['deviceExternalId'] = self.external_id

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

        timestamp = datetime.utcnow().replace(tzinfo=utc)

        syslog_msg = u'<{}>{} {}'.format(
            self.pri,
            timestamp.strftime('%b %d %H:%M:%S'),
            cef_message
        )

        self._actor.put(syslog_msg)

    def _eval_and_emit(self, indicator, value):
        indicators = [indicator]
        if (value['type'] == 'IPv4' or value['type'] == 'IPv6') and '-' in indicator:
            a1, a2 = indicator.split('-', 1)
            if a1 == a2:
                indicators = [a1]
            else:
                indicators = map(str, netaddr.IPRange(a1, a2).cidrs())

        for i in indicators:
            value['__indicator'] = i
            output = self._compiled_template.eval(locals_=self.locals, data=value)
            self._emit_cef(output)        

    @_counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        value['__method'] = 'update'
        self._eval_and_emit(indicator, value)

    @_counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        value['__method'] = 'withdraw'
        self._eval_and_emit(indicator, value)

    def mgmtbus_status(self):
        result = super(Output, self).mgmtbus_status()

        if self._actor is not None:
            result['statistics'].update(self._actor.statistics)

        return result

    def length(self, source=None):
        return self._actor.length()

    def start(self):
        super(Output, self).start()

        if self._actor is not None:
            self._actor.start()

    def stop(self):
        super(Output, self).stop()

        if self._actor is not None:
            self._actor.kill()

    @staticmethod
    def gc(name, config=None):
        ActorBaseFT.gc(name, config=config)

        if config is None:
            return

        template = config.get('template', None)
        if template is None:
            template = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_template.yml'.format(name)
            )

        try:
            os.remove(template)
        except:
            pass
