import argparse
import paho.mqtt.client as mqtt
import time
import jsonlines

sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config

intermediate_folder = config.get_folder("crawler.intermediate_folder")

class MyMQTTClass(mqtt.Client):
    apk = None
    responses = []

    def on_message_msgs(mosq, obj, other, msg):
        # This callback will only be called for messages with topics that match
        # $SYS/broker/messages/#
        #print("MESSAGES: " + msg.topic + " " + str(msg.qos) + " " + str(msg.payload))
        if msg is not None:
            message = str(msg.payload.decode("utf-8"))
            print(f"OnMsgs: {message}")
        else:
            print(f"OnMsgs: {msg}")
        print(other)


    def on_message_bytes(mosq, obj, other, msg):
        # This callback will only be called for messages with topics that match
        # $SYS/broker/bytes/#
        #print("BYTES: " + msg.topic + " " + str(msg.qos) + " " + str(msg.payload))
        if msg is not None:
            message = str(msg.payload.decode("utf-8"))
            print(f"onBytes: {message}")
        print(f"onBytes: {msg}")


    def on_message(mosq, obj, other, msg):
        # This callback will be called for messages that we receive that do not
        # match any patterns defined in topic specific callbacks, i.e. in this case
        # those messages that do not have topics $SYS/broker/messages/# nor
        # $SYS/broker/bytes/#
        #print(msg.topic + " " + str(msg.qos) + " " + str(msg.payload))
        message = str(msg.payload.decode("utf-8"))
        print(f"OnMge: {message}")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        #self._clean_session = False

        # Initialize variables
        self.server = None
        self.mqttclient = None
        self.mqttport = None
        self.username = None
        self.password = None
        self.subtopic = []
        self.pubtopic = []
        self.payloads = []
        self.mqtttransport = ""

        # Parse command-line arguments
        parser = argparse.ArgumentParser(description="MQTT Client")
        parser.add_argument('--apk', help="APK name")
        parser.add_argument('--server', help='MQTT server address')
        parser.add_argument('--port', help='MQTT port', nargs='?', type=int)
        parser.add_argument('--username', help='MQTT username', nargs='?')
        parser.add_argument('--password', help='MQTT password', nargs='?')
        parser.add_argument('--subtopic', help='Subscribe topic(s)', nargs='+')
        parser.add_argument('--pubtopic', help='Publish topic(s)', nargs='+')
        parser.add_argument('--payloads', help='Payload(s) to publish', nargs='*')
        parser.add_argument('--transport', help='MQTT transport method TCP or WebSockets', nargs='?')
        parser.add_argument('--client', help="Client ID", nargs='?')
        args = parser.parse_args()

        print(args)

        # Assign command-line arguments to instance variables
        self.apk = args.apk
        self.server = args.server
        self.mqttclient = args.client if args.client else ""
        self.mqttport = args.port if args.port else 1883
        self.username = args.username
        self.password = args.password
        self.subtopic = args.subtopic if args.subtopic else []
        self.pubtopic = args.pubtopic if args.pubtopic else []
        self.payloads = args.payloads if args.payloads else []
        self.mqtttransport = args.transport if args.transport else ""

        if self.mqtttransport == "ws":
            self.transport = "websockets"
        elif self.mqttport in (443, 80):
            self.transport = "websockets"

        self.client = self.mqttclient



    def on_connect(self, mqttc, obj, flags, reason_code, properties):
        print("[onConnect] rc: "+str(reason_code))
        #mqttc.disconnect()

    def on_connect_fail(self, mqttc, obj):
        print("Connect failed")

    def on_subscribe(self, mqttc, obj, mid, reason_code_list, properties):
        print("[onSubscribe]: "+str(mid)+" "+str(reason_code_list))

    def on_publish(self, mqttc, obj, mid, reason_codes, properties):
        print("[onPublish] mid: "+str(mid))

    def on_message(self, mqttc, obj, msg):
        print("[onMessage] " + msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
        write_output(filename=self.apk, message=msg, connection_data=f"{self.server}:{self.mqttport} ({self.username}, {self.password})", exception=None)

    def on_log(mqttc, obj, level, string):
        print(string)

    def run(self):

        username = self.username
        password = self.password
        server = self.server
        port = self.mqttport

        print(f"Connection to [{server}:{port}] using creds: {username} - {password}")

        if username != None and password != None:
            self.username_pw_set(username, password)
        
        self.connect(server, port, 60)
        time.sleep(2)

        for topic in self.subtopic:
            print(topic)
            self.subscribe(topic, qos=1)
            
        if "test.mosquitto" not in server:    
            self.subscribe('#', qos=1)

        
        for topic in self.pubtopic:
            for payload in self.payloads:
                self.publish(topic, bytes(payload, 'utf-8'), qos=1)
            self.publish(topic, "dummy payload", qos=1)

        startTime = time.time()
        runTime = 60
        while True:
            self.loop()
            currentTime = time.time()
            if (currentTime - startTime) > runTime:
                break
            
def write_output(filename, message, connection_data, exception):
    with jsonlines.open(intermediate_folder+filename+"-mqtturls.jsonl", mode='a') as writer:
        if message:
            writer.write(f"tp: {message.topic},pl: {message.payload} <|> {connection_data}\n")
        elif exception:
            # writer.write(f"error: {exception} <|> {connection_data} \n")
            print()
        else:
            writer.write(f"Should not happen <|> {connection_data}")

if __name__ == "__main__":
    mqttc = MyMQTTClass(mqtt.CallbackAPIVersion.VERSION2)
    try:
        rc = mqttc.run()
    except Exception as e:
        write_output(filename=mqttc.apk, message=None, connection_data=f"{mqttc.server}:{mqttc.mqttport} ({mqttc.username}, {mqttc.password})", exception=e)