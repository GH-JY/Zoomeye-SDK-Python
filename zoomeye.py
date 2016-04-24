#coding:utf-8
import json
import requests
import urllib


class zoomeye(object):
	'''
	调用Zoomeye api.这里输入帐号和密码.
	'''
	def __init__(self, username, password):
		self.baseurl = 'http://api.zoomeye.org/'
		self.username = username
		self.password = password
		self.s = requests.Session()
		self.headers = {}
		self.authdata = '{ "username": "' + username + '", "password": "' + password + '" }'

		try:
			resp = self.s.post(url=self.baseurl + 'user/login', data=self.authdata)
			if resp.status_code not in (200, 201):
				raise ZoomeyeError(resp.status_code, resp.content)
			self.token = json.loads(resp.content)['access_token']
			self.headers['Authorization'] = 'JWT ' + self.token
		except ZoomeyeError as e:
			e.print_error()
			exit(-1)

	def _handle_query(self, query):
		'''
		使查询从dict类型字符串.
		'''
		if isinstance(query, dict):
			query_dict = query
			query = ''
			for key in query_dict:
				query += str(key) + ':' + str(query_dict[key]) + ' '
			return query[:-1]
		else:
			return str(query)

	def resources_info(self):
		'''
		搜索到的资源信息.
		'''
		url = self.baseurl + 'resources-info'

		try:
			resp = self.s.get(url=url, headers=self.headers)
			if resp.status_code not in (200, 201):
				raise ZoomeyeError(resp.status_code, resp.content)
		except ZoomeyeError as e:
			e.print_error()
			exit(-1)

		return ZoomeyeResult(resp.content)

	def search(self, query, page=1, facets=[], t='host'):
		'''
		搜索主机搜索或者网络设备.
                
		'''
		query = urllib.quote('"' + self._handle_query(query) + '"')
		page = urllib.quote(str(page))
		facets = urllib.quote(str(facets)[1:-1])
		if t not in ('host', 'web'):
			t = 'host'

		try:
			resp = self.s.get(url=self.baseurl + '%s/search?query=%s&page=%s&facet=%s' % (t, query, page, facets), headers=self.headers)
			if resp.status_code not in (200, 201):
				raise ZoomeyeError(resp.status_code, resp.content)
		except ZoomeyeError as e:
			e.print_error()
			exit(-1)

		return ZoomeyeResult(resp.content)

class ZoomeyeResult(object):
	'''
	显示请求结果.
	'''
	def __init__(self, result):
		self.plan = ''
		self.resources = ''
		self.matches = ''
		self.facets = ''
		self.total = ''

		result = json.loads(result)
		if result.has_key('plan'):
			self.plan = result['plan']
		if result.has_key('resources'):
			self.resources = result['resources']
		if result.has_key('matches'):
			self.matches = result['matches']
			self.result_len = len(self.matches)
		if result.has_key('facets'):
			self.facets = result['facets']
		if result.has_key('total'):
			self.total = result['total']

	def get_ip_list(self, num=0):
		'''
		从结果中获取请求回来的ip列表.
		'''
		if not self.matches or not isinstance(self.matches[0]['ip'], basestring):
			return []

		ip_list = []
		if num <= 0 or num >= self.result_len:
			ip_num = self.result_len
		else:
			ip_num = num
		for i in range(0, ip_num):
			ip_list.append(self.matches[i]['ip'])
		return ip_list

	def get_portinfo_list(self, ip=[]):
		'''
		得到ip地址列表.
		'''
		if not self.matches or not self.matches[0].has_key('portinfo'):
			return {}

		portinfo_list = {}
		if isinstance(ip, basestring):
			ip_list = ip
		elif ip == []:
			ip_list = self.get_ip_list()
		else:
			ip_list = ip
		for i in range(0, self.result_len):
			if self.matches[i]['ip'] in ip_list:
				portinfo_list[self.matches[i]['ip']] = self.matches[i]['portinfo']
		return portinfo_list

	def get_site_list(self, num=0):
		'''
		从结果中获取到目标网站的列表.
		'''
		if not self.matches or not self.matches[0].has_key('site'):
			return []

		site_list = []
		if num <= 0 or num >= self.result_len:
			site_num = self.result_len
		else:
			site_num = num
		for i in range(0, site_num):
			site_list.append(self.matches[i]['site'])
		return site_list

	def get_webinfo_list(self, site=[]):
		'''
		获取到的目标列表的结果.
		'''
		if not self.matches or not self.matches[0].has_key('site'):
			return {}

		webinfo_list = {}
		if isinstance(site, basestring):
			site_list = site
		elif site == []:
			site_list = self.get_site_list()
		else:
			site_list = site
		for i in range(0, self.result_len):
			if self.matches[i]['site'] in site_list:
				webinfo_list[self.matches[i]['site']] = {}
				webinfo_list[self.matches[i]['site']]['db'] = self.matches[i]['db']
				webinfo_list[self.matches[i]['site']]['domains'] = self.matches[i]['domains']
				webinfo_list[self.matches[i]['site']]['language'] = self.matches[i]['language']
				webinfo_list[self.matches[i]['site']]['ip'] = self.matches[i]['ip']
				#webinfo_list[self.matches[i]['site']]['server'] = self.matches[i]['server']
				webinfo_list[self.matches[i]['site']]['webapp'] = self.matches[i]['webapp']
		return webinfo_list

class ZoomeyeError(Exception):
	'''
	错误处理.
	'''
	def __init__(self, status_code, content):
		self.status_code = status_code
		self.error = json.loads(content)['error']
		self.message = json.loads(content)['message']
		self.url = json.loads(content)['url']

	def print_error(self):
		'''
		输出错误信息，提醒使用者.
		'''
		print 'status_code: %d' % self.status_code
		print 'error: %s' % self.error
		print 'message: %s' % self.message
		print 'url: %s' % self.url
