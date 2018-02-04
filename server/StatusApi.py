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

import json
import StatusDb

class StatusApi(object):
    def __init__(self, root_dir):
        super(StatusApi, self).__init__()
        self.database = StatusDb.MongoDatabase(root_dir)

    def handle_graph_data_request(self, device_id, attributes, start_time):
        graph_data = []

        statuses = self.database.retrieve_status(device_id)
        if statuses is not None:
            for status in statuses:
                if "datetime" in status:
                    datetime_num = int(status["datetime"])
                    if datetime_num > start_time:
                        point_data = {}
                        point_data['datetime'] = datetime_num
                        for attribute in attributes:
                            # If the attribute doesn't exist for this timeslice then insert a zero
                            if attribute in status:
                                point_data[attribute] = status[attribute]
                            else:
                                point_data[attribute] = 0
                        graph_data.append(point_data)

        graph_str = "{\"points\":" + json.dumps(graph_data) + "}"
        return graph_str

    def handle_graph_color_request(self, device_id, attribute):
        return self.database.retrieve_device_color(device_id, attribute)

    def handle_api_1_0_request(self, args, values):
        if len(args) > 0:
            request = args[0]

            if request == 'upload':
                if "device_id" in values and "datetime" in values:
                    self.database.create_status(values)
                    return True, ""
            elif request == 'retrieve_graph_data':
                if "device_id" in values and "attributes" in values and "start_time" in values:
                    response = self.handle_graph_data_request(values["device_id"], values["attributes"].split(','), int(values["start_time"]))
                    return True, response
            elif request == 'retrieve_graph_color':
                if "device_id" in values and "attribute" in values:
                    response = self.handle_graph_color_request(values["device_id"], values["attribute"])
                    return True, response
        return False, ""
