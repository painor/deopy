import ast
import base64
import io
import logging
import marshal
import re
from enum import Enum
import py_compile
import requests
from uncompyle6 import PYTHON_VERSION
from uncompyle6.main import decompile


class Algorithms(Enum):
    NONE = 0
    MARSHAL = 1
    ZLIB = 2
    B64 = 3
    TRUST = 4
    BYTE_ESCAPE = 5
    ROT13 = 6
    GITHUB_LINK = 7
    B16 = 8


class Deopy:
    def __init__(self, verbose=False, python_version=PYTHON_VERSION):

        self.trust_regex = re.compile(r"eval\(compile\(base64.b64decode\(eval\('(.*)'\)\),'<string>','exec'\)\)")
        self.b64compile_regex = re.compile(r'g=compile\([d|r],"","exec"\)\nexec\(g\)')
        self.b16compile_regex = re.compile(r"exec\(compile\((data\(b\.b16decode\)), '<string>', 'exec'\)\)")
        self.zlib_regex = re.compile(r'exec\(zlib\.decompress')
        self.execx_regex = re.compile(r'exec\(x\)')
        self.execmand_regex = re.compile(r'exec\(mand\)')
        self.github_regex_find = re.compile(r'pip install --upgrade pip && pip install requests && pip install bs4')
        self.github_regex_capture = re.compile(r'https://raw.githubusercontent.com/(.*)/(.*)/master/(.*).py')
        self.marshal_loads_regex_1 = re.compile(r"import marshal\nexec\(marshal\.loads\(", flags=re.MULTILINE)
        self.marshal_loads_regex_2 = re.compile(r"import marshal as m\ndata = m.loads\(", flags=re.MULTILINE)
        self.python_version = python_version
        self.verbose = verbose
        self.algo_dict = {
            Algorithms.NONE: self.no_decrypt,
            Algorithms.ZLIB: self.decrypt_zlib,
            Algorithms.B64: self.decrypt_b64compile,
            Algorithms.B16: self.decrypt_b16,
            Algorithms.TRUST: self.decrypt_trust,
            Algorithms.BYTE_ESCAPE: self.decrypt_bytes_escape,
            Algorithms.ROT13: self.decrypt_rot13,
            Algorithms.GITHUB_LINK: self.decrypt_github,
            Algorithms.MARSHAL: self.decrypt_marshal,

        }

    def detect_algorithm(self, data: str) -> Algorithms:
        if self.trust_regex.search(data):
            return Algorithms.TRUST
        elif self.b64compile_regex.search(data):
            return Algorithms.B64
        elif self.zlib_regex.search(data):
            return Algorithms.ZLIB
        elif self.execx_regex.search(data):
            return Algorithms.BYTE_ESCAPE
        elif self.execmand_regex.search(data):
            return Algorithms.ROT13
        elif self.github_regex_find.search(data):
            return Algorithms.GITHUB_LINK
        elif self.marshal_loads_regex_1.search(data) or self.marshal_loads_regex_2.search(data):
            return Algorithms.MARSHAL
        elif self.b16compile_regex.search(data):
            return Algorithms.B16
        return Algorithms.NONE

    def auto_decrypt(self, data):
        counter = 0
        while True:
            algo = self.detect_algorithm(data)
            if algo == Algorithms.NONE:
                return self.algo_dict[algo](data, counter)
            counter += 1
            data = self.algo_dict[algo](data)

    def no_decrypt(self, data, number):
        if self.verbose:
            logging.info("The file was decrypted {} times.\n"
                         "This is the most I could compile. If the code is still not decrypted be sure to leave"
                         " a pull request with what you were left with".format(number))
        return data

    def decrypt_rot13(self, data: str) -> str:
        context = {}
        exec(self.execmand_regex.sub("context['result'] = mand", data))
        return context['result']

    def decrypt_marshal(self, data: str) -> str:
        if self.marshal_loads_regex_1.search(data):
            data = re.search(r"exec\(marshal\.loads\(b'([\S|\s]*)'\)\)", data).group(1)
        elif self.marshal_loads_regex_2.search(data):
            data = re.search(r"m\.loads\(b'([\S|\s]*)'\)", data).group(1)
        try:
            # this sometimes fails and I don't know why
            data = ast.literal_eval("b'" + data + "'")
        except ValueError as e:
            data = bytes(data, 'raw_unicode_escape')
        b = io.StringIO()
        decompile(self.python_version, marshal.loads(data), b, showast=False)
        return b.getvalue()

    def decrypt_github(self, data: str) -> str:
        link = self.github_regex_capture.search(data)
        data = requests.get(link.group()).text
        return base64.b64decode(data).decode("utf-8")

    def decrypt_bytes_escape(self, data: str) -> str:
        context = {}
        exec(self.execx_regex.sub("context['result'] = x", data))
        return context['result']

    def decrypt_b16(self, data: str) -> str:
        msg = self.b16compile_regex.search(data)
        context = {}
        exec(self.b16compile_regex.sub("context['result'] = {}".format(msg.group(1)), data))
        return context['result'].decode("utf-8")

    def decrypt_trust(self, data: str) -> str:
        msg = self.trust_regex.search(data)
        context = {}
        exec(self.trust_regex.sub("context['result'] = base64.b64decode(eval('{}'))".format(msg.group(1)), data))
        return context['result'].decode("utf-8")

    def decrypt_b64compile(self, data: str) -> str:
        context = {}
        exec(self.b64compile_regex.sub("context['result'] = d", data))
        return context["result"] if type(context["result"]) is str else context["result"].decode("utf-8")

    def decrypt_zlib(self, data: str) -> str:
        context = {}
        exec(self.zlib_regex.sub("context['result'] = (zlib.decompress", data))
        return context["result"] if type(context["result"]) is str else context["result"].decode("utf-8")
