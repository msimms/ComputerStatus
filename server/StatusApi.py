# MIT License
# 
# Copyright (c) 2018 Mike Simms
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import StatusDb

class StatusApi(object):
    def __init__(self, root_dir):
        super(StatusApi, self).__init__()
        self.database = StatusDb.MongoDatabase(root_dir)

    def format_graph_point(self, datetime_str, value):
        graph_str = "\t\t\t\t{ date: new Date(" + datetime_str + "), value: " + str(value) + " },\n"
        return graph_str

    def append_graph_point(self, datetime_str, status, key):
        if key in status:
            return self.format_graph_point(datetime_str, status[key])
        else:
            return self.format_graph_point(datetime_str, 0)

    def handle_graph_data_request(self, device_id, param, start_time):
        graph_str = "["
        statuses = self.database.retrieve_status(device_id)
        if statuses is not None:
            for status in statuses:
                if "datetime" in status:
                    datetime_num = int(status["datetime"]) * 1000
                    if datetime_num > start_time:
                        datetime_str = str(datetime_num)
                        graph_str += self.append_graph_point(datetime_str, status, param)
        graph_str += "]"
        return graph_str

    def handle_api_1_0_request(self, args, values):
        if len(args) > 0:
            request = args[0]
            if request == 'upload':
                if "device_id" in values and "datetime" in values:
                    self.database.create_status(values)
                    return True, ""
            elif request == 'graph_data':
                if "device_id" in values and "param" in values and "start_time" in values:
                    response = self.handle_graph_data_request(values["device_id"], values["param"], int(values["start_time"]))
                    return True, response
        return False, ""
