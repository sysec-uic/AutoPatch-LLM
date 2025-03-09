import logging
import time
import uuid

import paho.mqtt.client as mqtt_client
import paho.mqtt.enums as mqtt_enums


class MessageBrokerClient:
    def __init__(
        self, message_broker_host: str, message_broker_port: int, logger: logging.Logger
    ):
        self.message_broker_host = message_broker_host
        self.message_broker_port = message_broker_port
        self.logger = logger
        _client = self.connect_message_broker()
        self.client = _client
        self.client.enable_logger(self.logger)
        self.FIRST_RECONNECT_DELAY = 1
        self.RECONNECT_RATE = 2
        self.MAX_RECONNECT_COUNT = 12
        self.MAX_RECONNECT_DELAY = 60
        self.classname = self.__class__.__name__

    def connect_message_broker(self) -> mqtt_client.Client:
        # def on_message(client, userdata, message):
        #     self.logger.info("MessageBrokerClient - Message received: {message}")
        #     pass
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                self.logger.info("MessageBrokerClient - Connected to MQTT Broker!")
                self.logger.info(
                    "{classname} - Connected to MQTT Broker!", self.classname
                )
            else:
                self.logger.error(
                    "MessageBrokerClient - Failed to connect to MQTT Broker!"
                )
                self.logger.debug(
                    f"MessageBrokerClient - Failed to connect, return code {rc}\n"
                )

        def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
            self.logger.info(
                f"MessageBrokerClient - Disconnected with result code: {reason_code}"
            )
            reconnect_count, reconnect_delay = 0, self.FIRST_RECONNECT_DELAY
            while reconnect_count < self.MAX_RECONNECT_COUNT:
                self.logger.info(
                    f"MessageBrokerClient - Reconnecting in {reconnect_delay} seconds..."
                )
                time.sleep(reconnect_delay)

                try:
                    client.reconnect()
                    self.logger.info("MessageBrokerClient - Reconnected successfully!")
                    return
                except Exception as err:
                    logging.error(
                        f"MessageBrokerClient - {err}. Reconnect failed. Retrying..."
                    )

                reconnect_delay *= self.RECONNECT_RATE
                reconnect_delay = min(reconnect_delay, self.MAX_RECONNECT_DELAY)
                reconnect_count += 1
            self.logger.info(
                f"MessageBrokerClient - Reconnect failed after {reconnect_count} attempts. Exiting..."
            )

        def on_publish(client, userdata, mid):
            self.logger.info(f"MessageBrokerClient - Message {mid} published")

        def generate_uuid():
            return str(uuid.uuid4())

        # Generate a Client ID with the publish prefix.
        client_id = f"publish-{generate_uuid()}"
        client = mqtt_client.Client(
            client_id=client_id,
            callback_api_version=mqtt_enums.CallbackAPIVersion.VERSION2,
        )
        # client.username_pw_set(username, password)
        # client.tls_set(
        #     ca_certs=config["message_broker_ca_certs"], certfile=config["message_broker_certfile"], keyfile=config["message_broker_keyfile"]
        # )
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_publish = on_publish
        self.logger.info(
            "MessageBrokerClient - Connecting to MQTT Broker on {}:{}".format(
                self.message_broker_host, self.message_broker_port
            )
        )
        client.connect(self.message_broker_host, self.message_broker_port)
        return client

    def publish(self, topic: str, message: str) -> None:
        """
        Publish a message to the specified topic.
        """
        # at least once delivery, publish is non-blocking by default
        result: mqtt_client.MQTTMessageInfo = self.client.publish(topic, message, qos=1)
        if result.rc != mqtt_enums.MQTTErrorCode.MQTT_ERR_SUCCESS:
            self.logger.error(
                f"{self.classname} - Failed to send message to topic {topic}"
            )
            return
        self.logger.info(f"{self.classname} - Published message to topic {topic}")

    def consume(self, topic: str, message: str) -> None:
        """
        Consume a message from the specified topic.
        """
        self.client.subscribe(topic)

        pass
