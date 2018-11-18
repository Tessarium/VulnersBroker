from django.http import HttpResponse, JsonResponse
from django.template.response import TemplateResponse
from django.views import View
import requests


class ApiVulners(object):
    def __init__(self):
        """
            'main':         no,
            'search':       query,
            'software':     ['software', 'version', 'type'],
            'id':           id,
            'suggest':      ['type', 'fieldName'],
            'ai':           text,
            'archive':      type,
            'apikey':       keyID,
            'audit':        ['os', 'version', 'package'],
            'rules':        no,
            'autocomplete': query,
        """
        self.url = {
            'main':         "https://vulners.com/api/v3/",
            'search':       "https://vulners.com/api/v3/search/lucene/",
            'software':     "https://vulners.com/api/v3/burp/software/",
            'ai':           "https://vulners.com/api/v3/ai/scoretext/",
            'archive':      "https://vulners.com/api/v3/archive/collection/",
            'archive_dist': "https://vulners.com/api/v3/archive/distributive/",
            'apikey':       "https://vulners.com/api/v3/apiKey/valid/",
            'audit':        "https://vulners.com/api/v3/audit/audit/",
            'rules':        "https://vulners.com/api/v3/burp/rules/",
            'mapping':      "https://vulners.com/api/v3/search/getmapping/",
            'id':           "https://vulners.com/api/v3/search/id/",
            'suggest':      "https://vulners.com/api/v3/search/suggest/",
            'autocomplete': "https://vulners.com/api/v3/search/autocomplete/",
        }
        self.req = requests.session()

    def _api_key_url(self, method):
        try:
            return self.url[method.lower()]
        except Exception as exc:
            raise IndexError('Wrong API key') from exc

    @staticmethod
    def parameters(command):
        return (cmd for cmd in command)

    def main_res(self, url, *args):
        """
        :param url:
        :param args:
        :return:
        """
        response = self.req.get(url)
        return response.json()

    def search_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: query;
        :return:
        """
        try:
            prms_req = {
                'query': parameters.__next__()
            }
            response = self.req.post(url, json=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def mapping_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: type;
        :return:
        """
        try:
            prms_req = {
                'type': parameters.__next__()
            }
            response = self.req.post(url, json=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def software_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: software, version, type;
        :return:
        """
        try:
            prms_req = {
                'software': parameters.__next__(),
                'version': parameters.__next__(),
                'type': parameters.__next__()
            }
            response = self.req.post(url, json=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def id_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: id
        :return:
        """
        try:
            prms_req = {
                'id': str(parameters.__next__())
            }
            response = self.req.post(url, json=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def suggest_res(self, url, parameters=None):
        """
        suggest;distinct;affectedSoftware.name;
        :param url:
        :param parameters: type, fieldName;
        :return:
        """
        try:
            prms_req = {
                'type': parameters.__next__(),
                'fieldName': parameters.__next__()
            }
            response = self.req.get(url, params=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def ai_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: text;
        :return:
        """
        try:
            prms_req = {
                'text': parameters.__next__()
            }
            response = self.req.post(url, json=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def archive_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: type;
        :return:
        """
        try:
            prms_req = {
                'type': parameters.__next__()
            }
            response = self.req.post(url, params=prms_req)
            return {'OK': '"Request is correct, but the application cant give files yet"'}
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def archive_dist_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: os, version
        :return:
        """
        try:
            prms_req = {
                'os': parameters.__next__(),
                'version': parameters.__next__()
            }
            response = self.req.get(url, params=prms_req)
            return {'OK': '"Request is correct, but the application cant give files yet"'}
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def apikey_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: keyID;
        :return:
        """
        try:
            prms_req = {
                'keyID': parameters.__next__()
            }
            response = self.req.post(url, parameters=prms_req)
            return response.content
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def audit_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: os, version, package
        :return:
        """
        try:
            prms_req = {
                'os': parameters.__next__(),
                'version': parameters.__next__(),
                'package': parameters.__next__()
            }
            response = self.req.post(url, json=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def rules_res(self, url, *args):
        """
        :param url:
        :param args:
        :return:
        """
        response = self.req.get(url)
        return response.json()

    def autocomplete_res(self, url, parameters=None):
        """
        :param url:
        :param parameters: query;
        :return:
        """
        try:
            prms_req = {
                'query': parameters.__next__()
            }
            response = self.req.post(url, json=prms_req)
            return response.json()
        except StopIteration:
            return {'Error': '"You did not fill in all the fields, please fill out.")'}

    def api_command(self, request):
        try:
            command = request.POST['command'].split(';')
            prms = self.parameters(command)
            url = prms.__next__()

            method = getattr(self, '{}_res'.format(url))
            return JsonResponse(method(self._api_key_url(url), prms))
        except IndexError and AttributeError:
            return HttpResponse("Wrong request")


class MainVulners(View, ApiVulners):
    def __init__(self, **kwargs):
        super(View, self).__init__(**kwargs)

    def get(self, request):
        return TemplateResponse(request, 'main.html', {})

    def post(self, request):
        if request.is_ajax():
            result = self.api_command(request)
            return result
        return HttpResponse("Smt went wrong")
