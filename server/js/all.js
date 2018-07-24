// # MIT License
// 
// Copyright (c) 2018 Mike Simms
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

function serialize(list)
{
	var str = [];
    for (var i = 0; i < list.length; ++i)
		for (var key in list[i])
			str.push("\"" + encodeURIComponent(key) + "\": \"" + encodeURIComponent(list[i][key]) + "\"");
	json_str = "{" + str.join(",") + "}"
	return json_str
}

function send_post_request(url, params, result_text)
{
	var result = false;

	var xml_http = new XMLHttpRequest();
	var content_type = "application/json; charset=utf-8";

	xml_http.open("POST", url, false);
	xml_http.setRequestHeader('Content-Type', content_type);

	xml_http.onreadystatechange = function()
	{
		if (xml_http.readyState == XMLHttpRequest.DONE)
		{
			result_text.value = xml_http.responseText;
		}
		result = (xml_http.status == 200);
	}
	xml_http.send(serialize(params));
	return result;
}
