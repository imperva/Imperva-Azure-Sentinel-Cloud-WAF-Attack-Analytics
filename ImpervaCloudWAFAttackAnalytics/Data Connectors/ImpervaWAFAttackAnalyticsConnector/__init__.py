import requests
from requests.packages.urllib3.util.retry import Retry
import urllib3
import os
import zlib
import json
import azure.functions as func
import base64
import hmac
import hashlib
import datetime
import re
import logging
from .state_manager import StateManager

customer_id = os.environ['WorkspaceID'] 
shared_key = os.environ['WorkspaceKey']
imperva_waf_api_id = os.environ['ImpervaAPIID'] 
imperva_waf_api_key = os.environ['ImpervaAPIKey'] 
imperva_waf_log_server_uri = os.environ['ImpervaLogServerURI'] 
logs_encryption_private_key = ""


logging.basicConfig(level=logging.INFO)

####

connection_string = os.environ['AzureWebJobsStorage']
logAnalyticsUri = os.environ.get('logAnalyticsUri')

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):
    logAnalyticsUri = 'https://' + customer_id + '.ods.opinsights.azure.com'
pattern = r"https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$"
match = re.match(pattern,str(logAnalyticsUri))
if(not match):
    raise Exception("Invalid Log Analytics Uri.")


class ImpervaFilesHandler:

    def __init__(self, send_to_log_analytics=True):
        self.url = imperva_waf_log_server_uri
        retries = Retry(
            total=3,
            status_forcelist={500, 429},
            backoff_factor=1,
            respect_retry_after_header=True
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retries)
        self.session = requests.Session()
        self.session.mount('https://', adapter)
        self.auth = urllib3.make_headers(basic_auth='{}:{}'.format(imperva_waf_api_id, imperva_waf_api_key))
        self.files_array = self.list_index_file()
        self.sentinel = ProcessToSentinel(send_to_log_analytics)

    def list_index_file(self):
        files_array = []
        try:
            r = self.session.get(url="{}/{}".format(self.url, f"logs.index"),
                            headers= self.auth
                            )
            if 200 <= r.status_code <= 299:
                logging.info("Successfully downloaded index file.")
                for line in r.iter_lines():
                    files_array.append(line.decode('UTF-8'))
                return files_array
            elif r.status_code == 400:
                logging.error("Bad Request. The request was invalid or cannot be otherwise served."
                      " Error code: {}".format(r.status_code))
            elif r.status_code == 404:
                logging.error("Could not find index file. Response code is {}".format(r.status_code))
            elif r.status_code == 401:
                logging.error("Authorization error - Failed to download index file. Response code is {}".format(r.status_code))
            elif r.status_code == 429:
                logging.error("Rate limit exceeded - Failed to download index file. Response code is {}".format(r.status_code))
            else:
                if r.status_code is None:
                    logging.error("Something wrong. Error text: {}".format(r.text))
                else:
                    logging.error("Something wrong. Error code: {}".format(r.status_code))
        except Exception as err:
            logging.error("Something wrong. Exception error text within list_index_file function: {}".format(err))

    def last_file_point(self):
        try:
            if self.files_array is not None:
                state = StateManager(connection_string=connection_string)
                past_file = state.get()
                if past_file is not None:
                    logging.info("The last file point is: {}".format(past_file))
                    index = self.files_array.index(past_file)
                    files_arr = self.files_array[index + 1:]
                else:
                    files_arr = self.files_array
                logging.info("There are {} files in the list index file.".format(len(files_arr)))
                if self.files_array is not None:
                    current_file = self.files_array[-1]
                state.post(current_file)
                return files_arr
        except Exception as err:
            logging.error("Last point file detection error. Exception error text: {}".format(err))

    def download_files(self):
        files_for_download = self.last_file_point()
        if files_for_download is not None:
            for file in files_for_download:
                logging.info("Downloading file {}".format(file))
                self.download_file(file)

    def download_file(self, file_name):
        try:
            r = self.session.get(url="{}/{}".format(self.url, file_name), stream=True, headers=self.auth)
            if 200 <= r.status_code <= 299:
                logging.info("Successfully downloaded file: {}".format(file_name))
                self.decrypt_and_unpack_file(file_name, r.content)
                return r.status_code
            elif r.status_code == 400:
                logging.error("Bad Request. The request was invalid or cannot be otherwise served."
                      " Error code: {}".format(r.status_code))
            elif r.status_code == 404:
                logging.error("Could not find file {}. Response code: {}".format(file_name, r.status_code))
            elif r.status_code == 401:
                logging.error("Authorization error - Failed to download file {}. Response code: {}".format(file_name, r.status_code))
            elif r.status_code == 429:
                logging.error("Rate limit exceeded - Failed to downloadfile {}. Response code: {}".format(file_name, r.status_code))
            else:
                if r.status_code is None:
                    logging.error("Something wrong. Error text: {}".format(r.text))
                else:
                    logging.error("Something wrong. Error code: {}".format(r.status_code))
        except Exception as err:
            logging.error("Something wrong. Exception error text within download_file function: {}".format(err))

    def decrypt_and_unpack_file(self, file_name, file_content):
        logging.info("Unpacking and decrypting file {}".format(file_name))
        file_splitted = file_content.split(b"|==|\n")
        file_header = file_splitted[0].decode("utf-8")
        file_data = file_splitted[1]
        file_encryption_flag = file_header.find("key:")
        events_arr = []
        if file_encryption_flag == -1:
            try:
                events_data = zlib.decompressobj().decompress(file_data).decode("utf-8")
            except Exception as err:
                if 'while decompressing data: incorrect header check' in err.args[0]:
                    events_data = file_data.decode("utf-8")
                else:
                    logging.error("Error during decompressing and decoding the file with error message {}.".format(err))                   
        if events_data is not None:
            for line in events_data.splitlines():
                if "CEF" in line:
                    event_message = self.parse_cef(line)
                    events_arr.append(event_message)
        for chunk in self.gen_chunks_to_object(events_arr, chunksize=1000):
            # Enumerate the chunk to check for "msg" key
            self.sentinel.post_data(json.dumps(chunk), len(chunk), file_name)


    
    def parse_cef(self, cef_raw):
        # Splitting the CEF event into header and extension parts
        parts = cef_raw.split('|')
        if len(parts) < 8:
            print("Malformed CEF header, expected at least 8 parts but got:", len(parts))
            return {}
        
        # Extracting the header fields
        cef_version = parts[0].split(':')[1]
        device_vendor = parts[1]
        device_product = parts[2]
        device_version = parts[3]
        signature_id = parts[4]
        name = parts[5]
        severity = parts[6]
        
        # The remainder is the extension (key-value pairs)
        extension = '|'.join(parts[7:])  # Join back any parts that might be part of the extension

        # Initialize dictionary to hold key-value pairs
        parsed_cef = {
            "CEF Version": cef_version,
            "Device Vendor": device_vendor,
            "Device Product": device_product,
            "Device Version": device_version,
            "Signature ID": signature_id,
            "Name": name,
            "Severity": severity
        }

        # Regex to match key=value pairs where value is up to the next key or end of string
        kv_pattern = re.compile(r'(\w+)=((?:(?!\s\w+=).)*)')
        matches = kv_pattern.finditer(extension)

        for match in matches:
            key, value = match.groups()
            parsed_cef[key.strip()] = value.strip()

        # Adjusting the timestamp parsing to avoid deprecation warning
        if 'start' in parsed_cef and parsed_cef['start']:
            try:
                timestamp = datetime.datetime.fromtimestamp(int(parsed_cef['start'])/1000.0, datetime.timezone.utc).isoformat()
                parsed_cef['EventGeneratedTime'] = timestamp
            except:
                parsed_cef['EventGeneratedTime'] = ""
        else:
            parsed_cef['EventGeneratedTime'] = ""

        return parsed_cef


    def gen_chunks_to_object(self, object, chunksize=100):
        chunk = []
        for index, line in enumerate(object):
            if (index % chunksize == 0 and index > 0):
                yield chunk
                del chunk[:]
            chunk.append(line)
        yield chunk

class ProcessToSentinel:

    def __init__(self, send_to_log_analytics=True):
        self.logAnalyticsUri = logAnalyticsUri
        self.send_to_log_analytics = send_to_log_analytics

    def build_signature(self, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
        return authorization

    def post_data(self, body, chunk_count,file_name):
        if not self.send_to_log_analytics:
            logging.info("Data not sent to Log Analytics due to testing flag.")
            return
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        logging.info("The event that will be pushed to log analytics is: ")
        logging.info(body)
        signature = self.build_signature(rfc1123date, content_length, method, content_type,
                                         resource)
        uri = self.logAnalyticsUri + resource + '?api-version=2016-04-01'
        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': 'ImpervaWAFAttackAnalytics',
            'x-ms-date': rfc1123date,
            'time-generated-field':'EventGeneratedTime'
        }
        response = requests.post(uri, data=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            logging.info(response.status_code)
            logging.info(response.text)
            logging.info("Chunk was processed with {} events from the file: {}".format(chunk_count, file_name))
        else:
            logging.error("Error during sending events to Azure Sentinel. Response code:{}. File name: {}.".format(response.status_code,file_name))

def main(mytimer: func.TimerRequest)  -> None:
    if mytimer.past_due:
        logging.info('The timer is past due!')
    logging.info('Starting program')
    ifh = ImpervaFilesHandler()
    ifh.download_files()
            