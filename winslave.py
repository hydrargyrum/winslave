
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import ssl
from decorator import decorator
import os
import sys
import shutil
import stat
import subprocess
import optparse


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer, object):
	pass


class SSLThreadedHTTPServer(ThreadedHTTPServer):
	def __init__(self, address, handler_class, s_cert, c_cert):
		super(SSLThreadedHTTPServer, self).__init__(address, handler_class, bind_and_activate=False)
		self.old_socket = self.socket
		self.socket = ssl.wrap_socket(self.old_socket, certfile=s_cert, server_side=True, cert_reqs=ssl.CERT_REQUIRED, ca_certs=c_cert)
		self.server_bind()
		self.server_activate()


@decorator
def with_auth(func, *args, **kw):
	self = args[0]
	if not self.enforce_auth():
		return
	return func(*args, **kw)

class RequestHandler(BaseHTTPRequestHandler):
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
			return self.read_file(self.path[4:])
		else:
			self.send_error(404)

	@with_auth
	def do_PUT(self):
		if self.path.startswith('/fs/'):
			return self.write_file(self.path[4:])
		else:
			self.send_error(404)

	@with_auth
	def do_POST(self):
		if self.path == '/exec':
			self.exec_command()
		else:
			self.send_error(404)

	def allowed_path(self, path):
		return True

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
		props = os.stat(path)
		if not stat.S_ISREG(props.st_mode):
			self.send_error(403)
			return False
		else:
			return True

	def read_file(self, path):
		path = os.path.realpath('/%s' % path)

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
		path = os.path.realpath('/%s' % path)

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

	def exec_command(self):
		self.send_response(200)
		self.end_headers()
		src = self.rfile.read(int(self.headers.get('Content-Length', 0)))
		proc = subprocess.Popen(['/bin/sh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		proc.stdin.write(src)
		proc.stdin.close()
		shutil.copyfileobj(proc.stdout, self.wfile)
		proc.wait()


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

	server = SSLThreadedHTTPServer((opts.bind, opts.port), RequestHandler, opts.s_cert, opts.c_cert)
	server.serve_forever()

if __name__ == '__main__':
	main()

# curl -d @- https://localhost:9000/exec --cacert /tmp/pub.pem -E client-priv.pem -u foo:bar -v <<< 'ls /tmp'
