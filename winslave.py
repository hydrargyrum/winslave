
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import ssl
from urlparse import urlparse
import urllib
from decorator import decorator
import os
import sys
import shutil
import stat
import subprocess
import optparse
import shlex


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
	ACL = {'localhost': {'read_file': True, 'write_file': True, 'exec_command': True, 'fs_root': '/', 'command_root': '~/bin', 'exec_shell': False}}

	def finish_request(self, request, address):
		name = transform_subject_dict(request.getpeercert())['subject']['commonName']
		acl = self.ACL.get(name)
		if not acl:
			return
		self.RequestHandlerClass(request, address, self, acl=acl)


@decorator
def with_auth(func, *args, **kw):
	self = args[0]
	if not self.enforce_auth():
		return
	return func(*args, **kw)

class RequestHandler(BaseHTTPRequestHandler):
	def __init__(self, *a, **kw):
		self.acl = kw.pop('acl')
		BaseHTTPRequestHandler.__init__(self, *a, **kw)

	# helper
	def enforce_auth(self):
		if self.headers.get('Authorization') == 'Basic Zm9vOmJhcg==':
			return True
		else:
			self.send_error(401)
			return False

	@with_auth
	def do_GET(self):
		if self.path.startswith('/fs/'):
			path = urlparse(self.path[4:]).path
			return self.read_file(path)
		else:
			self.send_error(404)

	@with_auth
	def do_PUT(self):
		if self.path.startswith('/fs/'):
			path = urlparse(self.path[4:]).path
			return self.write_file(path)
		else:
			self.send_error(404)

	@with_auth
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
		if not self.enforce_file(path):
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
		if os.path.exists(path) and not self.enforce_file(path):
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

def main():
	parser = optparse.OptionParser()
	parser.add_option('-k', '--server-certificate', dest='s_cert', metavar='SERVER_KEY.PEM')
	parser.add_option('-c', '--client-certificate', dest='c_cert', metavar='CLIENTS_PUB_CERT.PEM')
	parser.add_option('-p', '--port', dest='port', type=int, metavar='PORT')
	parser.add_option('-b', '--bind', dest='bind', metavar='ADDRESS')
	parser.set_defaults(port=9000, bind='')
	opts, args = parser.parse_args()

	if not opts.s_cert or not opts.c_cert:
		parser.error('Missing --server-certificate or --client-certificate')

	server = ServerWithPermissions((opts.bind, opts.port), RequestHandler, opts.s_cert, opts.c_cert)
	server.serve_forever()


if __name__ == '__main__':
	main()
