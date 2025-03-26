# This file is a developement tool and example code only and can be used to test the MQTT broker.

from time import sleep
import paho.mqtt.client as mqtt


def on_connect(client, userdata, flags, rc):
    topic = "autopatch/crash_detail"
    client.subscribe(topic)
    print(f"subscribed to {topic}")
    print("publishing message from mqtt-produce-consume.py")

    count = 5
    topic = "autopatch/crash_detail"

    for i in range(count):
        message = '{ "attributes": { "type": "autopatch.crashdetail", "source": "autopatch.fuzzing-service", "subject": "complex3", "time": "2025-03-15T21:17:27Z", "specversion": "1.0", "id": "5e342659-a960-4c0f-8c6e-1df9e6911e50" }, "data": { "executable_name": "complex3", "crash_detail_base64": "aGVsbG8=", "is_input_from_file": true } }'
        client.publish(topic, message)
        sleep(1)
    for i in range(count):
        message = '{ "attributes": { "type": "autopatch.crashdetail", "source": "autopatch.fuzzing-service", "subject": "complex3", "time": "2025-03-15T21:17:27Z", "specversion": "1.0", "id": "5e342659-a960-4c0f-8c6e-1df9e6911e50" }, "data": { "executable_name": "complex3", "crash_detail_base64": "aGVsbG8=", "is_input_from_file": false } }'
        client.publish(topic, message)
        sleep(1)


def on_message(client, userdata, msg):
    print("Message received on topic: " + msg.topic)
    print("Message received: ", msg.payload.decode("utf-8"))


server = "mosquitto"
port = 1883
client = mqtt.Client()
# client = mqtt.Client(callback_api_version=mqtt_enums.CallbackAPIVersion.VERSION2)
client.on_message = on_message
client.on_connect = on_connect
print("connecting to mosquitto")
client.connect(server, port)
print("connected to mosquitto")

client.loop_forever()
