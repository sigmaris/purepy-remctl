import collections
import gssapi
import socket
import struct
import sys

__all__ = ('remctl', 'Remctl', 'RemctlError', 'RemctlNotOpenedError', 'RemctlProtocolError',
           'RemctlSimpleResult')

TOKEN_NOOP = 0x01
TOKEN_CONTEXT = 0x02
TOKEN_DATA = 0x04
TOKEN_CONTEXT_NEXT = 0x10
TOKEN_PROTOCOL = 0x40
MESSAGE_COMMAND = 1
MESSAGE_QUIT = 2
MESSAGE_OUTPUT = 3
MESSAGE_STATUS = 4
MESSAGE_ERROR = 5
MESSAGE_VERSION = 6
MESSAGE_NOOP = 7
MESSAGE_SIZE_LIMIT = 65536
STREAM_STDOUT = 1
STREAM_STDERR = 2


class RemctlError(Exception):
    pass


class RemctlNotOpenedError(Exception):
    pass


class RemctlProtocolError(Exception):
    cause = None
    code = None

    def __init__(self, value, *args):
        super(RemctlProtocolError, self).__init__(value, *args)
        self.value = value


Output = collections.namedtuple('Output', ['type', 'output', 'stream', 'status', 'error'])
RemctlSimpleResult = collections.namedtuple('RemctlSimpleResult', ['stdout', 'stderr', 'status'])


def _packet_generator(sock):
    data = b''
    while True:
        # Read the type and length header
        while len(data) < 5:
            bits = sock.recv(5 - len(data))
            if len(bits) == 0:
                # sock was closed
                return
            data += bits
        flags, length = struct.unpack('!BI', data)
        # Read the data itself
        data = b''
        while len(data) < length:
            bits = sock.recv(length - len(data))
            if len(bits) == 0:
                # sock was closed
                return
            data += bits
        # Now we have a full packet, yield it
        yield (flags, data)
        data = b''


def _encode_text(txt):
    if (
        (sys.version_info < (3, 0) and isinstance(txt, unicode))
        or (sys.version_info >= (3, 0) and isinstance(txt, str))
    ):
        return txt.encode()
    else:
        return txt


def remctl(host, port=4373, principal=None, command=None):
    # Kind of weird, but the original function signature has command after optional args
    if command is None:
        raise TypeError("The command argument must be provided.")

    stdout = ''
    stderr = ''
    status = None
    try:
        r = Remctl(host, port, principal)
        r.command(command)
        response_type = None
        while response_type != 'done':
            output = r.output()
            response_type = output.type
            if response_type == 'error':
                exc = RemctlProtocolError(output.output)
                exc.code = output.error
                raise exc
            elif response_type == 'output':
                if output.stream == STREAM_STDOUT:
                    stdout += output.output
                elif output.stream == STREAM_STDERR:
                    stderr += output.output
                else:
                    raise RemctlProtocolError("Unrecogised stream ID: {0}".format(output.stream))
            elif response_type == 'status':
                status = output.status
        r.close()
        return RemctlSimpleResult(stdout, stderr, status)
    except RemctlError as exc:
        wrapper = RemctlProtocolError(exc.args[0])
        wrapper.cause = exc
        raise wrapper


class Remctl(object):

    def __init__(self, host=None, port=4373, principal=None):
        super(Remctl, self).__init__()
        self.source = None
        self.credential = None
        self.timeout = 0
        self.sock = None
        self.receiver = None
        self.ctx = None
        self.commands = 0
        self.last_error = None

        if host is not None:
            self.open(host, port, principal)

    def set_credential(self, credential):
        if not isinstance(credential, gssapi.Credential):
            raise TypeError(
                "credential must be a gssapi.Credential, not {0}.".format(type(credential))
            )
        usage = credential.usage
        if usage != gssapi.C_INITIATE and usage != gssapi.C_BOTH:
            raise ValueError("credential has incorrect usage, it should be either gssapi.C_INITIATE"
                             "or gssapi.C_BOTH.")
        self.credential = credential

    def set_source_ip(self, source):
        self.source = source

    def set_timeout(self, timeout):
        if int(timeout) < 0:
            raise RemctlError("The timeout cannot be negative.")
        self.timeout = int(timeout)

    def open(self, host, port=4373, principal=None):
        if principal is None:
            gss_name = gssapi.Name('host@' + host, gssapi.C_NT_HOSTBASED_SERVICE)
        elif isinstance(principal, gssapi.Name):
            gss_name = principal
        else:
            gss_name = gssapi.Name(principal, gssapi.C_NT_HOSTBASED_SERVICE)

        args = [(host, port)]
        if self.timeout != 0:
            args.append(self.timeout)
        if self.source is not None:
            args.append((self.source, 0))
        sock = socket.create_connection(*args)

        sock.sendall(self._build_pkt(
            flags=(TOKEN_NOOP | TOKEN_CONTEXT_NEXT | TOKEN_PROTOCOL),
            data=b'', wrap=False
        ))

        ctx_args = [gss_name]
        if self.credential is not None:
            ctx_args.append(self.credential)
        ctx = gssapi.InitContext(*ctx_args, req_flags=(
            gssapi.C_MUTUAL_FLAG, gssapi.C_CONF_FLAG, gssapi.C_INTEG_FLAG,
            gssapi.C_REPLAY_FLAG, gssapi.C_SEQUENCE_FLAG
        ))
        in_token = None
        receiver = _packet_generator(sock)
        out_token = ctx.step()
        while not ctx.established:
            sock.sendall(self._build_pkt(
                flags=(TOKEN_CONTEXT | TOKEN_PROTOCOL),
                data=out_token, wrap=False
            ))
            try:
                flags, in_token = next(receiver)
            except StopIteration:
                sock.close()
                raise RemctlError("Network error: Server closed connection.")
            if not (flags & TOKEN_PROTOCOL):
                sock.close()
                raise RemctlError("Server is using remctl protocol version 1 which is unsupported.")
            if not (flags & TOKEN_CONTEXT):
                sock.close()
                raise RemctlError("Server failed to set TOKEN_CONTEXT flag on context packet.")
            out_token = ctx.step(in_token)
        if out_token:
            sock.sendall(self._build_pkt(
                flags=(TOKEN_CONTEXT | TOKEN_PROTOCOL),
                data=out_token, wrap=False
            ))
        if not ctx.mutual_auth_negotiated:
            sock.close()
            raise RemctlError("Could not negotiate mutual authentication")
        if not ctx.integrity_negotiated:
            sock.close()
            raise RemctlError("Could not negotiate integrity protection")
        if not ctx.confidentiality_negotiated:
            sock.close()
            raise RemctlError("Could not negotiate confidentiality protection")
        # otherwise, everything is fine, continue:
        self.last_error = None
        self.commands = 0
        self.sock = sock
        self.receiver = receiver
        self.ctx = ctx

    def command(self, command):
        if self.sock is None or self.ctx is None:
            raise RemctlNotOpenedError("Connection is not open.")
        if len(command) < 1:
            raise RemctlError("command must not be empty.")
        for data in self._build_command_data(command):
            self.sock.sendall(self._build_pkt(
                flags=(TOKEN_DATA | TOKEN_PROTOCOL),
                data=self._build_msg(MESSAGE_COMMAND, data)
            ))
        self.commands += 1

    def output(self):
        if self.sock is None or self.ctx is None:
            raise RemctlNotOpenedError("Connection is not open.")
        if self.commands > 0:
            try:
                flags, in_token = next(self.receiver)
            except StopIteration:
                self.close()
                raise RemctlError("Network error: Server closed connection.")
            message = self.ctx.unwrap(in_token)
            protocol_version, msg_type = struct.unpack('!BB', message[:2])
            data = message[2:]
            if protocol_version < 2:
                self.close()
                raise RemctlError("Protocol error: Server sent protocol version < 2.")
            if msg_type == MESSAGE_OUTPUT:
                stream, length = struct.unpack('!BI', data[:5])
                if len(data[5:]) != length:
                    raise RemctlError("Server claimed output length was "
                                      "{0} but sent {1} bytes.".format(length, len(data[5:])))
                return Output(type='output', output=data[5:], stream=stream, status=None, error=None)
            elif msg_type == MESSAGE_STATUS:
                self.commands -= 1
                (status,) = struct.unpack('!B', data)
                return Output(type='status', output=None, stream=None, status=status, error=None)
            elif msg_type == MESSAGE_ERROR:
                self.commands -= 1
                error, length = struct.unpack('!II', data[:8])
                if len(data[8:]) != length:
                    raise RemctlError("Server claimed error message length was "
                                      "{0} but sent {1} bytes.".format(length, len(data[8:])))
                self.last_error = data[8:]
                return Output(type='error', output=data[8:], stream=None, status=None, error=error)
            else:
                raise RemctlError("Unknown message type received: {0}".format(msg_type))
        else:
            return Output(type='done', output=None, stream=None, status=None, error=None)

    def noop(self):
        if self.sock is None or self.ctx is None:
            raise RemctlNotOpenedError("Connection is not open.")
        self.sock.sendall(self._build_pkt(
            flags=(TOKEN_DATA | TOKEN_PROTOCOL),
            data=self._build_msg(MESSAGE_NOOP, b'')
        ))
        try:
            flags, in_token = next(self.receiver)
        except StopIteration:
            self.close()
            raise RemctlError("Network error: Server closed connection.")
        message = self.ctx.unwrap(in_token)
        protocol_version, msg_type = struct.unpack('!BB', message[:2])
        if protocol_version != 3 or msg_type != MESSAGE_NOOP:
            raise RemctlError("Server does not support noop.")

    def close(self):
        try:
            self.sock.sendall(self._build_pkt(
                flags=(TOKEN_DATA | TOKEN_PROTOCOL),
                data=self._build_msg(MESSAGE_QUIT, b'')
            ))
        except:
            pass
        try:
            self.sock.close()
        except:
            pass
        self.sock = None
        self.receiver = None
        try:
            self.ctx.delete()
        except:
            pass
        self.ctx = None

    def _build_command_data(self, args, keepalive=True):
        ka_flag = 1 if keepalive else 0
        arg_segments = []
        argdata = b''
        argc = len(args)
        for arg in args:
            bytearg = _encode_text(arg)
            if len(argdata) + 4 + len(bytearg) > MESSAGE_SIZE_LIMIT:
                arg_segments.append(argdata)
                argdata = b''
            argdata += (struct.pack('!I', len(bytearg)) + bytearg)
        arg_segments.append(argdata)
        if len(arg_segments) == 1:
            header = struct.pack('!BBI', ka_flag, 0, argc)
            packets = [header + arg_segments[0]]
        else:
            header = struct.pack('!BBI', ka_flag, 1, argc)
            packets = [header + arg_segments[0]]
            for extra_arg_segment in arg_segments[1:-1]:
                packets.append(struct.pack('!BB', ka_flag, 2) + extra_arg_segment)
            packets.append(struct.pack('!BB', ka_flag, 3) + arg_segments[-1])
        return packets

    def _build_msg(self, msg_type, data):
        if msg_type == MESSAGE_NOOP:
            protocol_version = 3
        else:
            protocol_version = 2
        return struct.pack('!BB', protocol_version, msg_type) + data

    def _build_pkt(self, flags, data, wrap=True):
        if wrap:
            data = self.ctx.wrap(data, conf_req=True)
        return struct.pack('!BI', flags, len(data)) + data
