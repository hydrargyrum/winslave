
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import ssl
from urlparse import urlparse
import urllib
import os
import sys
import shutil
import stat
import subprocess
import optparse
import shlex
from ConfigParser import RawConfigParser


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer, object):
	pass


class SSLThreadedHTTPServer(ThreadedHTTPServer):
	def __init__(self, address, handler_class, s_cert, c_cert):
		super(SSLThreadedHTTPServer, self).__init__(address, handler_class, bind_and_activate=False)
		self.old_socket = self.socket
		self.socket = ssl.wrap_socket(self.old_socket, certfile=s_cert, server_side=True, cert_reqs=ssl.CERT_REQUIRED, ca_certs=c_cert)
		self.server_bind()
		self.server_activate()


class ServerWithPermissions(SSLThreadedHTTPServer):
	def __init__(self, *args, **kwargs):
		self.acl = kwargs.pop('acl')
		super(ServerWithPermissions, self).__init__(*args, **kwargs)

	def finish_request(self, request, address):
		name = transform_subject_dict(request.getpeercert())['subject']['commonName']
		acl = self.acl.get(name)
		if not acl:
			return
		self.RequestHandlerClass(request, address, self, acl=acl)


class RequestHandler(BaseHTTPRequestHandler):
	def __init__(self, *a, **kw):
		self.acl = kw.pop('acl')
		BaseHTTPRequestHandler.__init__(self, *a, **kw)

	def do_GET(self):
		if self.path.startswith('/fs/'):
			path = urlparse(self.path[4:]).path
			return self.read_file(path)
		else:
			self.send_error(404)

	def do_PUT(self):
		if self.path.startswith('/fs/'):
			path = urlparse(self.path[4:]).path
			return self.write_file(path)
		else:
			self.send_error(404)

	def do_POST(self):
		if self.path == '/exec_shell':
			self.exec_shell()
		elif self.path.startswith('/exec_command/'):
			command, args = self._command_and_args(self.path[len('/exec_command/'):])
			self.exec_command(command, args)
		else:
			self.send_error(404)

	def _command_and_args(self, path):
		command = urlparse(path).path
		args = shlex.split(urllib.unquote(urlparse(path).query))
		return (command, args)

	def allowed_path(self, path):
		return path.startswith(self._fs_root())

	def _oth_perm(self, path, perm):
		# very useless, as /exec can be used to circumvent that
		props = os.stat(path)
		if perm == 'r' and props.st_mode & stat.S_IROTH:
			return True
		elif perm == 'w' and props.st_mode & stat.S_IWOTH:
			return True
		else:
			return False

	def enforce_path_permission(self, path, perm):
		#~ perm = {'r': os.R_OK, 'w': os.W_OK}[perm]
		if not self.allowed_path(path):
			self.send_error(403)
			return False
		elif perm == 'r' and not os.path.exists(path):
			self.send_error(404)
			return False
		elif perm == 'w' and not os.path.exists(os.path.dirname(path)):
			self.send_error(404)
			return False
		elif perm == 'r' and not self._oth_perm(path, perm):
			self.send_error(403)
			return False
		else:
			return True

	def enforce_file(self, path):
		props = os.lstat(path)
		if not stat.S_ISREG(props.st_mode):
			self.send_error(403)
			return False
		else:
			return True

	def _fs_root(self):
		return os.path.expanduser(self.acl.get('fs_root') or '~')

	def _fs_path(self, path):
		path = os.path.normpath(path).lstrip('/')
		return os.path.realpath(os.path.join(self._fs_root(), path))
	
	def _command_root(self):
		return os.path.expanduser(self.acl.get('command_root') or '~/bin')
	
	def _command_path(self, path):
		path = os.path.normpath(path).lstrip('/')
		return os.path.realpath(os.path.join(self._command_root(), path))

	def read_file(self, path):
		path = self._fs_path(path)

		if not self.enforce_path_permission(path, 'r'):
			return
		elif not self.enforce_file(path):
			return
		elif not self.acl.get('read_file', False):
			self.send_error(403)
			return

		self.send_response(200) # Date+If-Modified-Since?

		with file(path, 'rb') as f:
			f.seek(0, os.SEEK_END)
			self.send_header('Content-Length', str(f.tell()))
			self.end_headers()

			f.seek(0, os.SEEK_SET)
			shutil.copyfileobj(f, self.wfile)

	def write_file(self, path):
		path = self._fs_path(path)

		if not self.enforce_path_permission(path, 'w'):
			return
		elif os.path.exists(path) and not self.enforce_file(path):
			return
		elif not self.acl.get('write_file', False):
			self.send_error(403)
			return

		with file(path, 'wb') as f:
			sz = int(self.headers.get('Content-Length', 0))
			while sz:
				buf = self.rfile.read(min(16384, sz))
				if not buf:
					break
				f.write(buf)
				sz -= len(buf)
		self.send_error(201)

	def exec_shell(self):
		if not self.acl.get('exec_shell', False):
			self.send_error(403)
			return

		self.send_response(200)
		self.end_headers()
		src = self.rfile.read(int(self.headers.get('Content-Length', 0)))
		proc = subprocess.Popen(['/bin/sh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		proc.stdin.write(src)
		proc.stdin.close()
		shutil.copyfileobj(proc.stdout, self.wfile)
		proc.wait()

	def exec_command(self, command, args):
		if not self.acl.get('exec_command', False):
			self.send_error(403)
			return

		command = self._command_path(command)
		if not command.startswith(self._command_root()):
			self.send_error(403)
			return

		self.send_response(200)
		self.end_headers()
		proc = subprocess.Popen([command] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		src = self.rfile.read(int(self.headers.get('Content-Length', 0)))
		proc.stdin.write(src)
		proc.stdin.close()
		shutil.copyfileobj(proc.stdout, self.wfile)
		proc.wait()


def transform_subject_dict(o):
	tuples = o['subject']
	o['subject'] = {}
	for t in tuples:
		o['subject'].update(dict(t))
	return o

def read_acl(filename):
	def get(section, option, default, method='get'):
		if config.has_option(section, option):
			return getattr(config, method)(section, option)
		else:
			return default

	getbool = lambda s, o, d: get(s, o, d, 'getboolean')

	config = RawConfigParser()
	config.read([filename])

	acl = {}
	for section in config.sections():
		name = get(section, 'commonName', section)
		acl[name] = {}
		acl[name]['read_file'] = getbool(section, 'read_file', False)
		acl[name]['write_file'] = getbool(section, 'write_file', False)
		acl[name]['fs_root'] = get(section, 'fs_root', None)
		acl[name]['exec_shell'] = getbool(section, 'exec_shell', False)
		acl[name]['exec_command'] = getbool(section, 'exec_command', False)
		acl[name]['command_root'] = get(section, 'command_root', None)

	return acl

def main():
	parser = optparse.OptionParser()
	parser.add_option('-k', '--server-certificate', dest='s_cert', metavar='SERVER_KEY.PEM')
	parser.add_option('-c', '--client-certificate', dest='c_cert', metavar='CLIENTS_PUB_CERT.PEM')
	parser.add_option('-p', '--port', dest='port', type=int, metavar='PORT')
	parser.add_option('-b', '--bind', dest='bind', metavar='ADDRESS')
	parser.add_option('-a', '--acl-file', dest='acl_file', metavar='FILE')
	parser.set_defaults(port=9000, bind='', acl_file='')
	opts, args = parser.parse_args()

	if not opts.s_cert or not opts.c_cert:
		parser.error('Missing --server-certificate or --client-certificate')
	if not opts.acl_file:
		sys.stderr.write('Warning: no --acl-file, the server will deny everything\n')
	acl = read_acl(opts.acl_file)

	server = ServerWithPermissions((opts.bind, opts.port), RequestHandler, opts.s_cert, opts.c_cert, acl=acl)
	server.serve_forever()

if __name__ == '__main__':
	main()
